package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

// 로그 찍는 함수, 내용이 많아지면 gz로 만듦
func initLogger() {
	log.SetOutput(&lumberjack.Logger{
		Filename:   "./logs/api.log",
		MaxSize:    1,  // 기본값 MB
		MaxBackups: 5,  // 총 제작되는 gz 갯수
		MaxAge:     30, // 며칠이 지난 오래된 로그를 자동으로 삭제
		Compress:   true,
	})
}

// 미들웨어
func MyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("요청 검사 시작")
		c.Next()
		fmt.Println("요청 처리 완료")
	}
}

// 로거
func JSONLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.WithFields(log.Fields{
			"ip":     c.ClientIP(),
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
		}).Info("Incoming Request")
		c.Next()
	}
}

func main() {
	initLogger()
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	router.Use(JSONLogger())
	{
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest

			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}

			c.JSON(http.StatusAccepted, gin.H{
				"message": "dummy register handler",
				"todo":    "replace with actual signup validation and insert query",
				"user": gin.H{
					"username": request.Username,
					"name":     request.Name,
					"email":    request.Email,
					"phone":    request.Phone,
				},
			})

			// 회원가입
			if err := insertTestData(store, request.Username, request.Name, request.Email, request.Phone, request.Password); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}

			// pw 확인 절차 추가
			ok2, err := Compare(user.Password, request.Password)
			if !ok || !ok2 || err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "dummy logout handler",
				"todo":    "replace with revoke or audit logic if needed",
			})
		})

		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusAccepted, gin.H{
				"message": "dummy withdraw handler",
				"todo":    "replace with password check and account delete logic",
				"user":    makeUserResponse(user),
			})
		})
	}

	protected := router.Group("/api")
	protected.Use(JSONLogger())
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy deposit handler",
				"todo":    "replace with balance increment query",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy withdraw handler",
				"todo":    "replace with balance check and decrement query",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy transfer handler",
				"todo":    "replace with transfer transaction and balance checks",
				"user":    makeUserResponse(user),
				"target":  request.ToUsername,
				"amount":  request.Amount,
			})
		})

		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			// 게시글 목록 조회
			selectTestData2_posts(store)

			c.JSON(http.StatusOK, PostListResponse{
				Posts: []PostView{
					{
						ID:          1,
						Title:       "Dummy Post",
						Content:     "This is a fixed dummy response. Replace this later with real board logic.",
						OwnerID:     1,
						Author:      "Alice Admin",
						AuthorEmail: "alice.admin@example.com",
						CreatedAt:   "2026-03-19T09:00:00Z",
						UpdatedAt:   "2026-03-19T09:00:00Z",
					},
				},
			})
		})

		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			// 게시글 추가
			if err := insertPost(store, request.Title, request.Content, user.ID); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			now := time.Now().Format(time.RFC3339)
			c.JSON(http.StatusCreated, gin.H{
				"message": "dummy create post handler",
				"todo":    "replace with insert query",
				"post": PostView{
					ID:          1,
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			})
		})

		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, PostResponse{
				Post: PostView{
					ID:          1,
					Title:       "Dummy Post",
					Content:     "This is a fixed dummy response. Replace this later with real board logic.",
					OwnerID:     1,
					Author:      "Alice Admin",
					AuthorEmail: "alice.admin@example.com",
					CreatedAt:   "2026-03-19T09:00:00Z",
					UpdatedAt:   "2026-03-19T09:00:00Z",
				},
			})
		})

		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			now := time.Now().Format(time.RFC3339)
			c.JSON(http.StatusOK, gin.H{
				"message": "dummy update post handler",
				"todo":    "replace with ownership check and update query",
				"post": PostView{
					ID:          1,
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					CreatedAt:   "2026-03-19T09:00:00Z",
					UpdatedAt:   now,
				},
			})
		})

		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "dummy delete post handler",
				"todo":    "replace with ownership check and delete query",
			})
		})
	}

	// 안전한 서버 종료를 위한 구문들
	// srv := &http.Server{
	// 	Addr:    ":8080",
	// 	Handler: router,
	// }
	// go func() {
	// 	srv.ListenAndServe()
	// }()

	// quit := make(chan os.Signal, 1)
	// signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	// <-quit

	// fmt.Println("서버 종료 준비 중...")
	// srv.Shutdown(context.Background())
	// fmt.Println("서버 안전한 종료")

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

// openStore DB 컨트롤
func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}

	// 추가 실패.
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

// 회원가입 추가
func insertTestData(s *Store, _username, _name, _email, _phone, _password string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO users VALUES(NULL,?,?,?,?,?, 0, 0)
	`

	// 중복 검사
	//if find1 := selectTestData1_users(s, _username, _email, _phone); find1 != nil {
	//	return fmt.Errorf("user already exists")
	//}

	// 패스워드 해싱
	_password_hash, err := Generate(_password)
	if err != nil {
		return err
	}

	result, err := tx.Exec(query, _username, _name, _email, _phone, _password_hash)
	if err != nil {
		fmt.Println("DB 삽입 실패:", err)
	} else {
		rowsAffected, _ := result.RowsAffected()
		fmt.Printf("DB 삽입 성공 %d\n", rowsAffected)
	}

	return tx.Commit()
}

// Generate는 평문의 패스워드에서 단방향 해시를 생성
func Generate(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	fmt.Println(hash)
	return string(hash), nil
}

// Compare는 단방향 해시와 평문 패스워드를 비교하여 에러를 반환한다
func Compare(hash, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, err
		}
		return false, err
	}
	return true, nil
}

// 탐색 1
func selectTestData1_users(s *Store, _username, _email, _phone string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if row := tx.QueryRow("SELECT id FROM users WHERE username = (?)", _username); row != nil {
		fmt.Println("DB 탐색 실패:")
		return err
	} else if row := tx.QueryRow("SELECT id FROM users WHERE email = (?)", _email); row != nil {
		fmt.Println("DB 탐색 실패:")
		return err
	} else if row := tx.QueryRow("SELECT id FROM users WHERE phone = (?)", _phone); row != nil {
		fmt.Println("DB 탐색 실패:")
		return err
	}

	fmt.Println("DB 탐색 성공")
	return nil
}

// 탐색 2
func selectTestData2_posts(s *Store) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT * FROM posts")
	if err != nil {
		return err
	}
	for rows.Next() {

	}

	fmt.Println("DB 탐색 성공")
	return tx.Commit()
}

// 게시글 추가
func insertPost(s *Store, _title, _content string, _uid uint) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO posts VALUES(NULL, ?, ?, ?, ?, ?)
	`
	result, err := tx.Exec(query, _title, _content, _uid, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	if err != nil {
		fmt.Println("DB 삽입 실패:", err)
	} else {
		rowsAffected, _ := result.RowsAffected()
		fmt.Printf("DB 삽입 성공 %d\n", rowsAffected)
	}

	return tx.Commit()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users
		WHERE username = ?
	`, strings.TrimSpace(username))

	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1

	return user, true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

// fe 페이지 캐싱으로 테스트에 혼동이 있어, 별도 처리없이 main에 두시면 될 것 같습니다
// registerStaticRoutes 는 정적 파일(HTML, JS, CSS)을 제공하는 라우트를 등록한다.
func registerStaticRoutes(router *gin.Engine) {
	// 브라우저 캐시 비활성화 — 정적 파일과 루트 경로에만 적용
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
