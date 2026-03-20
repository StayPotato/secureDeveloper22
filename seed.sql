INSERT INTO users (id, username, name, email, phone, password, balance, is_admin)
VALUES
    (1, 'alice', 'Alice Admin', 'alice.admin@example.com', '010-1111-2222', '$2a$10$6fhfSH9wrWvi.4prHH.KmO.qIP1Du817q.rV8amJaQfvB3h28.yx2', 150000, 1),
    (2, 'bob', 'Bob Member', 'bob.member@example.com', '010-3333-4444', '$2a$10$G6w.83M1iBYYlLFAI7s/v.dwQz/7ZcMQ3ZHseNZzVhNo/FR7T4EVq', 90000, 0),
    (3, 'charlie', 'Charlie Member', 'charlie.member@example.com', '010-5555-6666', '$2a$10$u43W3m7.o0YoXf9NDfPtvOoI0Qv/LC0boY7OvBZcq2.8SJXznF44.', 64000, 0)
ON CONFLICT(id) DO UPDATE SET
    username = excluded.username,
    name = excluded.name,
    email = excluded.email,
    phone = excluded.phone,
    password = excluded.password,
    balance = excluded.balance,
    is_admin = excluded.is_admin;
