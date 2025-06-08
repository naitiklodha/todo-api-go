package main

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	ginSwagger "github.com/swaggo/gin-swagger"
	swaggerFiles "github.com/swaggo/files"
		_ "todo-api/docs" 
)

// @title Todo API
// @version 1.0
// @description This is a sample Todo API built with Gin and GORM.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// Models
type User struct {
    ID             uint   `json:"id" gorm:"primaryKey"`
    Username       string `json:"username" gorm:"unique;not null"`
    Email          string `json:"email" gorm:"unique;not null"`
    Password       string `json:"-" gorm:"not null"`
    OrganizationID uint   `json:"organization_id" gorm:"not null"`
    Organization   Organization `json:"organization" gorm:"foreignKey:OrganizationID"`
    Todos          []Todo `json:"todos,omitempty" gorm:"foreignKey:UserID"`
    CreatedAt      time.Time `json:"created_at"`
    UpdatedAt      time.Time `json:"updated_at"`
}

type Organization struct {
    ID        uint   `json:"id" gorm:"primaryKey"`
    Name      string `json:"name" gorm:"unique;not null"`
    Users     []User `json:"users,omitempty" gorm:"foreignKey:OrganizationID"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type Todo struct {
    ID          uint   `json:"id" gorm:"primaryKey"`
    Title       string `json:"title" gorm:"not null"`
    Description string `json:"description"`
    Completed   bool   `json:"completed" gorm:"default:false"`
    UserID      uint   `json:"user_id" gorm:"not null"`
    User        User   `json:"user" gorm:"foreignKey:UserID"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// Request/Response structs
type LoginRequest struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
    Username       string `json:"username" binding:"required"`
    Email          string `json:"email" binding:"required,email"`
    Password       string `json:"password" binding:"required,min=6"`
    OrganizationID uint   `json:"organization_id" binding:"required"`
}

type CreateTodoRequest struct {
    Title       string `json:"title" binding:"required"`
    Description string `json:"description"`
}

type UpdateTodoRequest struct {
    Title       *string `json:"title,omitempty"`
    Description *string `json:"description,omitempty"`
    Completed   *bool   `json:"completed,omitempty"`
}

type AuthResponse struct {
    Token string `json:"token"`
    User  User   `json:"user"`
}

type ErrorResponse struct {
    Error string `json:"error"`
}

type MessageResponse struct {
    Message string `json:"message"`
}

type HealthResponse struct {
    Status string `json:"status"`
}

var db *gorm.DB
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
    UserID uint `json:"user_id"`
    jwt.RegisteredClaims
}

func initDB() {
    var err error
    db, err = gorm.Open(sqlite.Open("todo.db"), &gorm.Config{})
    if err != nil {
        panic("Failed to connect to database")
    }

    db.AutoMigrate(&Organization{}, &User{}, &Todo{})

    var orgCount int64
    db.Model(&Organization{}).Count(&orgCount)
    if orgCount == 0 {
        defaultOrg := Organization{Name: "Default Organization"}
        db.Create(&defaultOrg)
    }
}

func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
            tokenString = tokenString[7:]
        }

        token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        claims, ok := token.Claims.(*Claims)
        if !ok {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
            c.Abort()
            return
        }

        var user User
        if err := db.Preload("Organization").First(&user, claims.UserID).Error; err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
            c.Abort()
            return
        }

        c.Set("user", user)
        c.Next()
    }
}

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func generateToken(userID uint) (string, error) {
    claims := &Claims{
        UserID: userID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

// Handlers

// @Summary Register a new user
// @Description Register a new user with username, email, password, and organization ID.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param user body RegisterRequest true "User registration details"
// @Success 201 {object} AuthResponse
// @Failure 400 {object} ErrorResponse "Bad Request"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /register [post]
func register(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var org Organization
    if err := db.First(&org, req.OrganizationID).Error; err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Organization not found"})
        return
    }

    hashedPassword, err := hashPassword(req.Password)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }

    // Create user
    user := User{
        Username:       req.Username,
        Email:          req.Email,
        Password:       hashedPassword,
        OrganizationID: req.OrganizationID,
    }

    if err := db.Create(&user).Error; err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Username or email already exists"})
        return
    }

    db.Preload("Organization").First(&user, user.ID)

    token, err := generateToken(user.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

    c.JSON(http.StatusCreated, AuthResponse{Token: token, User: user})
}

// @Summary Log in a user
// @Description Authenticate a user and return a JWT token.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param credentials body LoginRequest true "User login credentials"
// @Success 200 {object} AuthResponse
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /login [post]
func login(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var user User
    if err := db.Preload("Organization").Where("username = ?", req.Username).First(&user).Error; err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }

    if !checkPasswordHash(req.Password, user.Password) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }

    token, err := generateToken(user.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

    c.JSON(http.StatusOK, AuthResponse{Token: token, User: user})
}

// @Summary Create a new todo
// @Description Create a new todo for the authenticated user.
// @Tags Todos
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param todo body CreateTodoRequest true "Todo details"
// @Success 201 {object} Todo
// @Failure 400 {object} ErrorResponse "Bad Request"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /todos [post]
func createTodo(c *gin.Context) {
    user := c.MustGet("user").(User)
    
    var req CreateTodoRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    todo := Todo{
        Title:       req.Title,
        Description: req.Description,
        UserID:      user.ID,
    }

    if err := db.Create(&todo).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create todo"})
        return
    }

    // Load user info for response
    db.Preload("User").First(&todo, todo.ID)

    c.JSON(http.StatusCreated, todo)
}

// @Summary Get all todos for the user's organization
// @Description Retrieve all todos belonging to users within the authenticated user's organization.
// @Tags Todos
// @Security BearerAuth
// @Produce json
// @Success 200 {array} Todo
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /todos [get]
func getTodos(c *gin.Context) {
    user := c.MustGet("user").(User)
    
    var todos []Todo
    // Get all todos from users in the same organization
    if err := db.Preload("User").
        Joins("JOIN users ON todos.user_id = users.id").
        Where("users.organization_id = ?", user.OrganizationID).
        Find(&todos).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch todos"})
        return
    }

    c.JSON(http.StatusOK, todos)
}

// @Summary Get a todo by ID
// @Description Retrieve a specific todo by its ID, ensuring it belongs to the authenticated user's organization.
// @Tags Todos
// @Security BearerAuth
// @Produce json
// @Param id path int true "Todo ID"
// @Success 200 {object} Todo
// @Failure 400 {object} ErrorResponse "Bad Request"
// @Failure 404 {object} ErrorResponse "Not Found"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /todos/{id} [get]
func getTodoByID(c *gin.Context) {
    user := c.MustGet("user").(User)
    
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid todo ID"})
        return
    }

    var todo Todo
    if err := db.Preload("User").
        Joins("JOIN users ON todos.user_id = users.id").
        Where("todos.id = ? AND users.organization_id = ?", id, user.OrganizationID).
        First(&todo).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
        return
    }

    c.JSON(http.StatusOK, todo)
}

// @Summary Update a todo by ID
// @Description Update an existing todo by its ID. Only the owner of the todo can update it.
// @Tags Todos
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "Todo ID"
// @Param todo body UpdateTodoRequest true "Updated todo details"
// @Success 200 {object} Todo
// @Failure 400 {object} ErrorResponse "Bad Request"
// @Failure 403 {object} ErrorResponse "Forbidden"
// @Failure 404 {object} ErrorResponse "Not Found"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /todos/{id} [put]
func updateTodo(c *gin.Context) {
    user := c.MustGet("user").(User)
    
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid todo ID"})
        return
    }

    var todo Todo
    if err := db.First(&todo, id).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
        return
    }

    if todo.UserID != user.ID {
        c.JSON(http.StatusForbidden, gin.H{"error": "You can only update your own todos"})
        return
    }

    var req UpdateTodoRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    if req.Title != nil {
        todo.Title = *req.Title
    }
    if req.Description != nil {
        todo.Description = *req.Description
    }
    if req.Completed != nil {
        todo.Completed = *req.Completed
    }

    if err := db.Save(&todo).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update todo"})
        return
    }

    db.Preload("User").First(&todo, todo.ID)

    c.JSON(http.StatusOK, todo)
}

// @Summary Delete a todo by ID
// @Description Delete an existing todo by its ID. Only the owner of the todo can delete it.
// @Tags Todos
// @Security BearerAuth
// @Produce json
// @Param id path int true "Todo ID"
// @Success 200 {object} MessageResponse "Todo deleted successfully"
// @Failure 400 {object} ErrorResponse "Bad Request"
// @Failure 403 {object} ErrorResponse "Forbidden"
// @Failure 404 {object} ErrorResponse "Not Found"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /todos/{id} [delete]
func deleteTodo(c *gin.Context) {
    user := c.MustGet("user").(User)
    
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid todo ID"})
        return
    }

    var todo Todo
    if err := db.First(&todo, id).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
        return
    }

    // Check if user owns the todo
    if todo.UserID != user.ID {
        c.JSON(http.StatusForbidden, gin.H{"error": "You can only delete your own todos"})
        return
    }

    if err := db.Delete(&todo).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete todo"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Todo deleted successfully"})
}

// @Summary Get all organizations
// @Description Retrieve a list of all organizations.
// @Tags Organizations
// @Produce json
// @Success 200 {array} Organization
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Router /organizations [get]
func getOrganizations(c *gin.Context) {
    var organizations []Organization
    if err := db.Find(&organizations).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organizations"})
        return
    }

    c.JSON(http.StatusOK, organizations)
}

// @Summary Health check
// @Description Check the health status of the API.
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse "API is healthy"
// @Router /health [get]
func main() {
    initDB()

    r := gin.Default()

    // CORS middleware
    r.Use(func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    })

    r.POST("/register", register)
    r.POST("/login", login)
    r.GET("/organizations", getOrganizations)

    protected := r.Group("/")
    protected.Use(authMiddleware())
    {
        protected.POST("/todos", createTodo)
        protected.GET("/todos", getTodos)
        protected.GET("/todos/:id", getTodoByID)
        protected.PUT("/todos/:id", updateTodo)
        protected.DELETE("/todos/:id", deleteTodo)
    }

    r.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "healthy"})
    })

    r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))


    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    r.Run(":" + port)
}