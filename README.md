# Spring Boot JWT Authentication Project

This is a Spring Boot project that provides a secure JWT-based authentication system.

## Prerequisites

- Java 17
- Maven
- PostgreSQL

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/your-repo.git
   ```

2. **Configure the database:**
   - Open `src/main/resources/application.properties` and update the following properties with your PostgreSQL credentials:
     ```properties
     spring.datasource.url=jdbc:postgresql://localhost:5432/your-database
     spring.datasource.username=your-username
     spring.datasource.password=your-password
     ```

3. **Build the project:**
   ```bash
   mvn clean install
   ```

4. **Run the application:**
   ```bash
   mvn spring-boot:run
   ```

## API Endpoints

The application exposes the following API endpoints:

- `POST /api/auth/register`: Register a new user.
- `POST /api/auth/login`: Authenticate a user and receive a JWT.
- `GET /api/secure/resource`: Access a secure resource (requires a valid JWT).

For more details on the API, you can access the Swagger UI at `http://localhost:8080/swagger-ui.html`.