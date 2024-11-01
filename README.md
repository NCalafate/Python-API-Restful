> IPS - Escola Superior de Tecnologia de Setúbal
>
> LEI - Computação Paralela e Distribuída 2023 / 2024


# Practical Assignment #3 – API Restful

## Solution

During the implementation of the RESTful API for Practical Assignment #3, we focused on robust authentication validation to ensure security and access control. All responses were standardized in JSON, providing consistency and ease of use for developers.

We optimized API performance by using efficient data structures and optimized database queries. A modular approach was adopted in implementing the API methods, promoting organization and code reusability.

### Methods

#### app.py / authenticate_user: Authorization

- This method authenticates a user based on credentials provided in the HTTP request header.
- If the credentials are valid, the method returns the user’s 'id'. If not, an HTTP 401 error is generated, indicating that authentication failed due to invalid credentials

#### app.py / is_user_project: int, int

- This method checks if a specific project belongs to the specified user.
- If the project belongs to the user, the method returns True and allows the process to continue. Otherwise, if the project exists but does not belong to the user, it returns an HTTP 403 error. If the project does not exist, it returns an HTTP 404 error.

#### app.py / handle_response: int, str | any

- This method prepares and returns an HTTP response based on the provided status code.
- For 200 codes (success), it returns the response directly. For codes in the 400 range (client errors), it prepares and returns an appropriate HTTP error. If the code does not fit any of these categories, an error code 418 is returned by default.

#### app.py / timestamp

- This method returns the current day as a string in the format 'YYYY-MM-DD'

#### app.py / before_request
- This method is executed before each request to configure the rate limiter based on the user’s role.
- It disables rate limiting if the application is in test mode or if the user is an admin.


### Pylint

- The file app.py was analyzed and corrected using Pylint, achieving the maximum score of 10.00/10.

## Extras

### Private Messages

- We added support for private messages to the API, introducing new routes and dedicated methods to facilitate secure communication between users.
- This update expands the API’s capabilities, providing an efficient and secure way to exchange private messages within the application.

### Rate Limiting
We implemented rate limiting to control the number of requests each user can make in a given time period, using the `flask_limiter` library.

- Objective: To protect the API against abuse and overload, ensuring appropriate resource usage.
- Configuration: The rate is configured to allow 1 request per minute for endpoints (for demonstration purposes).
- Deactivation: Rate limiting is disabled for users with an admin role and during testing to avoid interference, except when specifically testing the limiter.

### PythonAnywhere

The application is hosted on the PythonAnywhere platform 

### Unit Tests / testsExtra.py

- In the file testsExtra.py, 37 additional tests were implemented covering specific routes for the 5 main types of objects: user, project, task, msgs, and limiter.
- These tests were designed to validate the functionality and integrity of each object’s operations in the application.
