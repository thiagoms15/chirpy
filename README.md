# Chirpy Backend - Go Study Project

This is a backend API server written in Go, created as a study project to learn backend development and API design using Go. It includes user authentication, JWT handling, and basic CRUD operations for a microblogging-style application called Chirpy.

## Features

- User registration and login with bcrypt password hashing
- JWT access and refresh token authentication
- CRUD operations for chirps (short posts)
- Admin metrics and reset endpoint
- In-memory and PostgreSQL database interactions using `sqlc`
- Middleware for tracking request metrics

---

## Requirements

- Go 1.20+
- PostgreSQL
- `goose` (for migrations)
- `sqlc` (for typed SQL queries)

---

## Setup Instructions

1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/chirpy-backend.git
cd chirpy-backend
cp .env.example .env
```
