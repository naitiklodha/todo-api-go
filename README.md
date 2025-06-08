# Todo API

This is a sample Todo API built with Gin and GORM, providing user authentication, organization management, and todo functionalities.

## Features

  * **User Authentication**: Register and log in users using JWT (JSON Web Tokens).
  * **Organization Management**: Users are associated with organizations, enabling organization-scoped data access.
  * **Todo Management**: Standard CRUD (Create, Read, Update, Delete) operations for todos. Users can only manage their own todos.
  * **Swagger Documentation**: Interactive API documentation for easy exploration and testing.
  * **SQLite Database**: Uses a lightweight, file-based SQLite database for data storage.

## Technologies Used

  * **Go**: Programming language.
  * **Gin Gonic**: High-performance HTTP web framework.
  * **GORM**: ORM (Object-Relational Mapping) library for database interactions.
  * **golang-jwt/jwt**: Go package for JWTs.
  * **x/crypto/bcrypt**: For secure password hashing.
  * **swaggo/gin-swagger**: Integrates Swagger UI with Gin.

## Getting Started

Follow these steps to set up and run the Todo API on your local machine.

### Prerequisites

  * Go (version 1.18 or higher recommended)
  * Git

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/naitiklodha/todo-api-go.git
    cd todo-api
    ```

2.  **Install Go dependencies:**

    ```bash
    go mod tidy
    ```

3.  **Generate Swagger documentation (if you modify API annotations):**
    If you change the comments that define the API endpoints for Swagger, you'll need to regenerate the documentation.

    ```bash
    go install [github.com/swaggo/swag/cmd/swag@latest](https://github.com/swaggo/swag/cmd/swag@latest)
    swag init
    ```

### Configuration

The application requires a `JWT_SECRET` for token signing. You can also configure the port.

1.  **Set JWT Secret:**
    Create a `.env` file in the root directory of the project (next to `main.go`). Add your secret key to this file:

    ```
    JWT_SECRET="a_very_strong_and_random_secret_key_for_jwt_signing"
    ```

2.  **Set Port (Optional):**
    By default, the API runs on port `8080`. To use a different port, add it to your `.env` file:

    ```
    PORT="your_desired_port_number"
    ```

### Running the Application

1.  **Start the API server:**

    ```bash
    go run main.go
    ```

    The API will now be running, typically on `http://localhost:8080`.

### Database

The application uses an SQLite database named `todo.db`, which will be created automatically in the project's root directory upon the first run if it doesn't exist. GORM handles the database schema creation and migrations. A default organization named "Default Organization" will also be created if no organizations are found in the database.

## API Documentation and Usage

Once the application is running, you can access the interactive API documentation through Swagger UI.

### Accessing Swagger UI

Open your web browser and navigate to:

`http://localhost:8080/swagger/index.html`

Here you can see all available endpoints, their expected inputs, and example responses. You can also test the API directly from this interface.

### Example Workflow:

1.  **Get Organizations**: Find the ID of an existing organization (e.g., "Default Organization").
2.  **Register User**: Use the `/register` endpoint with a username, email, password, and an `organization_id`.
3.  **Login User**: Use the `/login` endpoint with the registered username and password to obtain a JWT `token`.
4.  **Authenticated Requests**: Use the `token` obtained from login in the `Authorization` header as `Bearer <YOUR_JWT_TOKEN>` for protected routes like creating, getting, updating, or deleting todos.

## Project Structure

```
.
├── docs/                # Generated Swagger documentation files
│   ├── docs.go
│   ├── swagger.json
│   └── swagger.yaml
├── .env                 # Environment variables (ignored by Git)
├── .gitignore           # Specifies intentionally untracked files to ignore
├── go.mod               # Go module definition file
├── go.sum               # Checksums for Go module dependencies
├── main.go              # Main application entry point and logic
├── README.md            # This README file
└── todo.db              # SQLite database file (ignored by Git)
```

## License

MIT