"""
 Flask REST application

"""
import http
from datetime import datetime

from flask import Flask, request, jsonify, make_response, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import Authorization

from models import Database

# ==========
#  Settings
# ==========

app = Flask(__name__)
app.config['STATIC_URL_PATH'] = '/static'

# ==========
#  Database
# ==========

# Creates a sqlite database in memory
db = Database(filename=':memory:', schema='schema.sql')
db.recreate()


# ===========
#  Web views
# ===========

@app.route('/')
def index():
    """ Index route """
    return app.send_static_file('index.html')


# ===========
#  API views
# ===========

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)


@app.before_request
def before_request():
    """
    Function executed before each request to configure rate limiting based on user role.

    Disables rate limiting if the application is in testing mode or if the user has an admin role.
    """
    if request.endpoint == 'index':
        return

    if app.config['TESTING']:
        limiter.enabled = False
        return

    role = get_user_role()
    limiter.enabled = role != 'admin'


@app.route('/api/user/register/', methods=['POST'])
def user_register():
    """
    Registers a new user.
    Does not require authorization.

    """
    data = request.get_json()
    fields = ["name", "email", "username", "password"]

    for field in fields:
        if field not in data or not data[field]:
            handle_response(code=400, response=f'Missing field: {field}')

    name = data.get('name')
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    user_exists = db.execute_query('SELECT * FROM user WHERE username=? OR email=?',
                                   (username, email)).fetchone()
    if user_exists:
        handle_response(code=400, response="This user already exists")

    user_id = db.execute_update(
        'INSERT INTO user (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)',
        (name, email, username, password, 'user',))

    user = db.execute_query('SELECT id, name, email, username, role FROM user WHERE id=?',
                            (user_id,)).fetchone()

    return handle_response(code=201, response=user)


@app.route('/api/user/', methods=['GET', 'PUT'])
@limiter.limit("1 per minute")
def user_detail():
    """
    Returns or updates current user.
    Requires authorization.

    """
    user_id = authenticate_user(auth=request.authorization)

    user = db.execute_query('SELECT * FROM user WHERE id=?', (user_id,)).fetchone()

    if user_id:
        if request.method == 'GET':
            # Returns user data
            return handle_response(code=200, response=user)

        if request.method == 'PUT':
            data = request.get_json()

            data_name = data.get('name')
            data_email = data.get('email')
            data_username = data.get('username')
            data_password = data.get('password')

            data_fields = ['name', 'email', 'username', 'password']
            if not any(data.get(field) for field in data_fields):
                handle_response(code=400, response="No fields to update")

            db.execute_update('UPDATE user SET name=COALESCE(?, name), email=COALESCE(?, email), '
                              'username=COALESCE(?, username), password=COALESCE(?, '
                              'password)WHERE id=?',
                              (data_name, data_email, data_username, data_password, user_id))

            user = db.execute_query('SELECT * FROM user WHERE id=?', (user_id,)).fetchone()

            return handle_response(code=200, response=user)

    return None


@app.route('/api/user/messages/', methods=['GET', 'POST'])
@limiter.limit("1 per minute")
def messages():
    """
    Handles sending and receiving messages.
    Requires authorization.
    """
    user_id = authenticate_user(auth=request.authorization)

    if request.method == 'GET':
        # Returns the list of messages for the authenticated user
        msgs = db.execute_query('SELECT * FROM message WHERE receiver_id=? OR sender_id=?',
                                (user_id, user_id)).fetchall()
        return handle_response(code=200, response=msgs)

    if request.method == 'POST':
        # Sends a new message
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        date = timestamp()

        if not receiver_id or not content:
            handle_response(code=400, response="Receiver ID and content are required")

        user_receiver = db.execute_query('SELECT id FROM user WHERE id=?',
                                         (receiver_id,)).fetchone()
        if not user_receiver:
            handle_response(code=400, response="Invalid user")

        message_id = db.execute_update(
            'INSERT INTO message (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)',
            (user_id, receiver_id, content, date))

        message = db.execute_query('SELECT * FROM message WHERE id=?', (message_id,)).fetchone()
        return handle_response(code=201, response=message)

    return None


@app.route('/api/projects/', methods=['GET', 'POST'])
@limiter.limit("1 per minute")
def project_list():
    """
    Project list.
    Requires authorization.
    """
    # Get authenticated user ID
    user_id = authenticate_user(auth=request.authorization)

    if request.method == 'GET':
        # Returns the list of projects of a user
        projects = db.execute_query('SELECT * FROM project WHERE user_id=?', (user_id,)).fetchall()

        if len(projects) == 0:
            return handle_response(code=204)

        return handle_response(code=200, response=projects)

    if request.method == 'POST':
        # Adds a project to the list
        request_body = request.get_json()
        data_title = request_body.get('title')
        data_today = timestamp()

        if not data_title:
            handle_response(code=400)

        project_id = db.execute_update('INSERT INTO project VALUES (null, ?, ?, ?, ?)',
                                       (user_id, data_title, data_today, data_today,))

        project = db.execute_query('SELECT * FROM project WHERE id=?', (project_id,)).fetchone()
        return handle_response(code=201, response=project)

    return None


@app.route('/api/projects/<int:pk>/', methods=['GET', 'PUT', 'DELETE'])
@limiter.limit("1 per minute")
def project_detail(pk):
    """
    Project detail.
    Requires authorization.
    """
    user_id = authenticate_user(auth=request.authorization)

    if request.method == 'GET':
        # Returns a project
        if is_user_project(user_id=user_id, project_id=pk):
            project = db.execute_query('SELECT * FROM project WHERE id=? and user_id=?',
                                       (pk, user_id)).fetchone()
            return handle_response(code=200, response=project)

    if request.method == 'PUT':
        # Updates a project
        request_body = request.get_json()
        data_title = request_body.get('title')
        data_date = timestamp()

        if data_title is None:
            handle_response(code=400, response="Invalid Field")

        if is_user_project(user_id=user_id, project_id=pk):
            project_id = db.execute_update(
                'UPDATE project SET title=COALESCE(?, title), last_updated=? WHERE id =?',
                (data_title, data_date, pk,))

            project = db.execute_query('SELECT * FROM project WHERE id=?', (project_id,)).fetchone()

            if not project:
                handle_response(code=410)
            return handle_response(code=200, response=project)

    if request.method == 'DELETE':
        # Deletes a project
        if is_user_project(user_id=user_id, project_id=pk):
            cursor_tasks = db.execute_query('DELETE FROM task WHERE project_id=?', (pk,))
            cursor_projects = db.execute_query('DELETE FROM project WHERE id=?', (pk,))

            if (cursor_tasks.rowcount + cursor_projects.rowcount) == 0:
                handle_response(code=404)
            return handle_response(code=204)

    return None


@app.route('/api/projects/<int:pk>/tasks/', methods=['GET', 'POST'])
@limiter.limit("1 per minute")
def task_list(pk):
    """
    Task list.
    Requires authorization.
    """

    user_id = authenticate_user(auth=request.authorization)

    if request.method == 'GET':
        # Returns the list of tasks of a project
        if is_user_project(user_id=user_id, project_id=pk):
            task = db.execute_query('SELECT task.* FROM task  WHERE project_id=?', (pk,)).fetchall()

            if not task:
                handle_response(code=404)

            if len(task) == 0:
                return handle_response(code=204)

            return handle_response(code=200, response=task)

    if request.method == 'POST':
        # Adds a task to project
        request_body = request.get_json()
        data_title = request_body.get('title')
        data_completed = request_body.get('completed', 0)
        data_date = timestamp()

        if data_title is None:
            handle_response(code=400)

        if is_user_project(user_id=user_id, project_id=pk):
            task_id = db.execute_update('INSERT INTO task VALUES (null, ?, ?, ?, ?)',
                                        (pk, data_title, data_date, data_completed))

            task = db.execute_query('SELECT * FROM task WHERE id=?', (task_id,)).fetchone()

            return handle_response(code=201, response=task)

    return None


@app.route('/api/projects/<int:pk>/tasks/<int:task_pk>/', methods=['GET', 'PUT', 'DELETE'])
@limiter.limit("1 per minute")
def task_detail(pk, task_pk):
    """
    Task detail.
    Requires authorization.
    """

    user_id = authenticate_user(auth=request.authorization)

    if request.method == 'GET':
        # Returns a task
        if is_user_project(user_id=user_id, project_id=pk):
            task = db.execute_query('SELECT task.* FROM task WHERE task.id=? and project_id=?',
                                    (task_pk, pk)).fetchone()

            if not task:
                handle_response(code=404)

            return handle_response(code=200, response=task)

    if request.method == 'PUT':
        # Updates a task
        request_body = request.get_json()
        data_title = request_body.get('title')
        data_completed = request_body.get('completed')

        if data_title is None and data_completed is None:
            handle_response(code=400)

        if is_user_project(user_id=user_id, project_id=pk):
            cursor_tasks = db.execute_query(
                'UPDATE task SET title=COALESCE(?, title), completed=COALESCE(?, completed) WHERE '
                'id=? and project_id=?', (data_title, data_completed, task_pk, pk,))

            if cursor_tasks.rowcount == 0:
                handle_response(code=404)

            task = db.execute_query('SELECT * FROM task WHERE id=? and project_id =?',
                                    (task_pk, pk)).fetchone()

            return handle_response(code=200, response=task)

    if request.method == 'DELETE':
        # Deletes a task
        if is_user_project(user_id=user_id, project_id=pk):
            cursor_tasks = db.execute_query('DELETE FROM task WHERE id=? and project_id=?',
                                            (task_pk, pk))

            if cursor_tasks.rowcount == 0:
                handle_response(code=404)

            return handle_response(code=204)

    return None


def authenticate_user(auth: Authorization):
    """
        Authenticate a user based on provided credentials.

        Args:
            auth (Authorization): An object containing user authentication information.
            This object must have 'username' and 'password' attributes.

        Returns:
            int: The user's ID if authentication is successful.
            None: If authentication fails due to missing credentials or invalid credentials.
    """

    if not auth or not auth.username or not auth.password:
        handle_response(code=401, response="Username and password required")

    user = db.execute_query('SELECT id FROM user WHERE username=? and password=?',
                            (auth.username, auth.password,)).fetchone()

    if not (user and 'id' in user):
        handle_response(code=401, response="Invalid Credentials")

    return user.get('id')


def is_user_project(user_id: int, project_id: int):
    """
    Check if a project belongs to a specific user.

    Args:
        user_id (int): The ID of the user.
        project_id (int): The ID of the project.

    Returns:
        bool: True if the project belongs to the user, False otherwise.
    """
    project = db.execute_query('SELECT user_id FROM project WHERE id=?', (project_id,)).fetchone()

    if project is None:
        handle_response(code=404)

    if project.get('user_id') != user_id:
        handle_response(code=403)

    return True


def handle_response(code: int = 418, response: any or str = None):
    """
    Handle HTTP responses based on the status code provided.

    Args:
        code (int, optional): The HTTP status code to handle. Defaults to 418.
        response (any | str, optional): The response data or message.
                                        Defaults to None. If provided and the
                                        code is 200-299, it will be returned
                                        in the response. If the code is 400-499
                                        and no response is provided, the HTTP
                                        status code phrase will be used.

    Returns:
        A Flask response object for successful responses (200-299) or aborts
        with an error message for client errors (400-499).
    """

    if 200 <= code <= 299:
        return make_response(jsonify(response), code)

    if 400 <= code <= 499:
        status_code_message = response if response else http.HTTPStatus(code).phrase
        response_error = {"error": {"code": code, "message": status_code_message}}
        abort(make_response(jsonify(response_error), code))

    return handle_response(code=418)


def timestamp():
    """
    Generates a timestamp of the current date in 'YYYY-MM-DD' format.

    Returns:
        str: The current date as a string in 'YYYY-MM-DD' format.
    """
    return datetime.today().strftime('%Y-%m-%d')


def get_user_role():
    """
    Retrieves the role of the currently authenticated user.

    Returns:
        str: The role of the authenticated user.
    """
    user_id = authenticate_user(auth=request.authorization)
    user = db.execute_query('SELECT role FROM user WHERE id=?', (user_id,)).fetchone()
    return user['role']


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
