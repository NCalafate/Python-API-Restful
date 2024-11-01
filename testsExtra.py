"""
 Tests the application API

"""

import base64
import unittest

from flask import json

from app import app, db


def auth_header(username, password):
    """Returns the authorization header."""
    credentials = f'{username}:{password}'
    b64credentials = base64.b64encode(credentials.encode()).decode('utf-8')
    return {'Authorization': f'Basic {b64credentials}'}


class TestBase(unittest.TestCase):
    """Base for all tests."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.db = db
        self.db.recreate()

    def tearDown(self):
        pass


class TestMsgs(TestBase):
    """Tests for the messages endpoints."""

    def setUp(self):
        super().setUp()
        self.user1 = {
            "name": "User One", "email": "user1@example.com", "username": "user1",
            "password": "pass", "role": "admin"}
        self.user2 = {
            "name": "User Two", "email": "user2@example.com", "username": "user2",
            "password": "pass", "role": "admin"}
        self.register_user(self.user1)
        self.register_user(self.user2)
        self.credentials_user1 = auth_header(self.user1['username'], self.user1['password'])
        self.credentials_user2 = auth_header(self.user2['username'], self.user2['password'])

    def register_user(self, user_data):
        self.client.post('/api/user/register/', data=json.dumps(user_data),
                         content_type='application/json')

    def test_get_messages_empty(self):
        """Tests getting messages when there are no messages."""
        res = self.client.get('/api/user/messages/', headers=self.credentials_user1)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.data), [])

    def test_post_message(self):
        """Tests sending a message."""
        message_data = {
            'receiver_id': 2, 'content': 'Hello, this is a test message.'}
        res = self.client.post('/api/user/messages/', headers=self.credentials_user1,
                               data=json.dumps(message_data), content_type='application/json')
        self.assertEqual(res.status_code, 201)
        message = json.loads(res.data)
        self.assertEqual(message['content'], 'Hello, this is a test message.')
        self.assertEqual(message['receiver_id'], 2)

    def test_post_message_missing_fields(self):
        """Tests sending a message with missing fields."""
        message_data = {
            'content': 'Hello, this is a test message without receiver.'}
        res = self.client.post('/api/user/messages/', headers=self.credentials_user1,
                               data=json.dumps(message_data), content_type='application/json')
        self.assertEqual(res.status_code, 400)

    def test_post_message_invalid_receiver(self):
        """Tests sending a message to a non-existent receiver."""
        message_data = {
            'receiver_id': 999,
            'content': 'Hello, this is a test message to a non-existent receiver.'}
        res = self.client.post('/api/user/messages/', headers=self.credentials_user1,
                               data=json.dumps(message_data), content_type='application/json')
        self.assertEqual(res.status_code, 400)


class TestUsers(TestBase):
    """Tests for the user endpoints."""

    def setUp(self):
        super().setUp()
        self.user_data = {
            "name": "John Doe", "email": "john@example.com", "username": "john", "password": "1234",
            "role": "admin"}
        self.credentials = auth_header(self.user_data['username'], self.user_data['password'])

    # def register_user(self, name, email, username, password):
    #    return self.client.post('/api/user/register/',
    #                            data=json.dumps(dict(name=name, email=email, username=username,
    #                            password=password)),
    #                            content_type='application/json')

    def register_user(self, **user_data):
        """Helper method to register a user."""
        return self.client.post('/api/user/register/', data=json.dumps(user_data),
                                content_type='application/json')

    def test_register_user(self):
        """Tests registering a new user."""
        res = self.register_user(**self.user_data)
        self.assertEqual(res.status_code, 201)

    def test_register_existing_user(self):
        """Tests registering a user that already exists."""
        self.register_user(**self.user_data)
        res = self.register_user(**self.user_data)
        self.assertEqual(res.status_code, 400)

    def test_register_user_missing_fields(self):
        """Tests registering a user with missing fields."""
        user_data = {"name": "John Doe", "username": "john", "password": "1234"}
        res = self.register_user(**user_data)
        self.assertEqual(res.status_code, 400)

    def test_correct_credentials(self):
        """Tests the user with correct credentials."""
        credentials = auth_header('homer', '1234')
        res = self.client.get('/api/user/', headers=credentials)
        self.assertEqual(res.status_code, 200)

    def test_wrong_credentials(self):
        """Tests the user with incorrect credentials."""
        credentials = auth_header('no-user', 'no-password')
        res = self.client.get('/api/user/', headers=credentials)
        self.assertEqual(res.status_code, 401)

    def test_get_user_without_auth(self):
        """Tests getting user data without authorization."""
        res = self.client.get('/api/user/')
        self.assertEqual(res.status_code, 401)

    def test_get_user_correct_credentials(self):
        """Tests the user with correct credentials."""
        self.register_user(**self.user_data)
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        res = self.client.get('/api/user/', headers=credentials)
        self.assertEqual(res.status_code, 200)

    def test_get_nonexistent_user(self):
        """Tests getting a user that doesn't exist."""
        res = self.client.get('/api/user/9999/', headers=self.credentials)
        self.assertEqual(res.status_code, 404)

    def test_update_user(self):
        """Tests updating user data."""
        self.register_user(**self.user_data)
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        update_data = {"name": "John Updated", "email": "john_updated@example.com"}
        res = self.client.put('/api/user/', headers=credentials, data=json.dumps(update_data),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)

    def test_update_user_missing_fields(self):
        """Tests updating user data with missing fields."""
        self.register_user(**self.user_data)
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        update_data = {"name": "John Updated"}
        res = self.client.put('/api/user/', headers=credentials, data=json.dumps(update_data),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)

    def test_update_user_invalid_fields(self):
        """Tests updating user data with invalid fields."""
        self.register_user(**self.user_data)
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        update_data = {"CENAS": "CPD"}
        res = self.client.put('/api/user/', headers=credentials, data=json.dumps(update_data),
                              content_type='application/json')
        self.assertEqual(res.status_code, 400)

    def test_get_user_after_update(self):
        """Tests getting user data after updating user info."""
        self.register_user(**self.user_data)
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        update_data = {"name": "John Updated", "email": "john_updated@example.com"}
        self.client.put('/api/user/', headers=credentials, data=json.dumps(update_data),
                        content_type='application/json')
        res = self.client.get('/api/user/', headers=credentials)
        self.assertEqual(res.status_code, 200)
        self.assertIn("John Updated", res.get_data(as_text=True))
        self.assertIn("john_updated@example.com", res.get_data(as_text=True))


class TestProjects(TestBase):
    """Tests for the project endpoints."""

    def setUp(self):
        super().setUp()
        self.user_data = {
            "name": "John Doe", "email": "john@example.com", "username": "john", "password": "1234",
            "role": "admin"}
        self.register_user(self.user_data)
        self.credentials = auth_header(self.user_data['username'], self.user_data['password'])

    def register_user(self, user_data):
        self.client.post('/api/user/register/', data=json.dumps(user_data),
                         content_type='application/json')

    def test_create_project(self):
        """Tests creating a new project."""
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        project_data = {"title": "New Project"}
        res = self.client.post('/api/projects/', headers=credentials, data=json.dumps(project_data),
                               content_type='application/json')
        self.assertEqual(res.status_code, 201)

    def test_create_project_missing_title(self):
        """Tests creating a project with missing title."""
        project_data = {}
        res = self.client.post('/api/projects/', headers=self.credentials,
                               data=json.dumps(project_data), content_type='application/json')
        self.assertEqual(res.status_code, 400)

    def test_get_projects(self):
        """Tests getting a list of projects."""
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        project_data = {"title": "New Project"}
        self.client.post('/api/projects/', headers=credentials, data=json.dumps(project_data),
                         content_type='application/json')
        res = self.client.get('/api/projects/', headers=credentials)
        self.assertEqual(res.status_code, 200)
        self.assertGreater(len(res.json), 0)

    def test_get_nonexistent_project(self):
        """Tests getting a project that doesn't exist."""
        res = self.client.get('/api/projects/9999/', headers=self.credentials)
        self.assertEqual(res.status_code, 404)

    def test_update_project(self):
        """Tests updating a project."""
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        project_data = {"title": "New"}
        res = self.client.post('/api/projects/', headers=credentials, data=json.dumps(project_data),
                               content_type='application/json')
        project_id = res.json['id']
        updated_data = {"title": "Updated Project"}
        res = self.client.put(f'/api/projects/{project_id}/', headers=credentials,
                              data=json.dumps(updated_data), content_type='application/json')
        self.assertEqual(res.status_code, 200)

    def test_update_project_invalid_fields(self):
        """Tests updating a project with invalid fields."""
        project_data = {"title": "New"}
        res = self.client.post('/api/projects/', headers=self.credentials,
                               data=json.dumps(project_data), content_type='application/json')
        project_id = res.json['id']
        updated_data = {"invalid_field": "Invalid Data"}
        res = self.client.put(f'/api/projects/{project_id}/', headers=self.credentials,
                              data=json.dumps(updated_data), content_type='application/json')
        self.assertEqual(res.status_code, 400)

    def test_delete_project(self):
        """Tests deleting a project."""
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        project_data = {"title": "New Project2830"}
        res = self.client.post('/api/projects/', headers=credentials, data=json.dumps(project_data),
                               content_type='application/json')
        project_id = res.json['id']
        res = self.client.delete(f'/api/projects/{project_id}/', headers=credentials)
        self.assertEqual(res.status_code, 204)

    def test_delete_nonexistent_project(self):
        """Tests deleting a project that doesn't exist."""
        res = self.client.delete(f'/api/projects/9999/', headers=self.credentials)
        self.assertEqual(res.status_code, 404)

    def test_delete_project_wrong_user(self):
        """Tests deleting a project."""
        credentials = auth_header(self.user_data['username'], self.user_data['password'])
        project_data = {"title": "New Project2835"}
        res = self.client.post('/api/projects/', headers=credentials, data=json.dumps(project_data),
                               content_type='application/json')
        project_id = res.json['id']
        credentialsWrong = auth_header('homer', '1234')
        res = self.client.delete(f'/api/projects/{project_id}/', headers=credentialsWrong)
        self.assertEqual(res.status_code, 403)


class TestTasks(TestBase):
    """Tests for the task endpoints."""

    def setUp(self):
        super().setUp()
        self.user_data = {
            "name": "John Doe", "email": "john@example.com", "username": "john", "password": "1234",
            "role": "admin"}
        self.register_user(self.user_data)
        self.credentials = auth_header(self.user_data['username'], self.user_data['password'])
        self.project_data = {"title": "New Project"}
        project_res = self.client.post('/api/projects/', headers=self.credentials,
                                       data=json.dumps(self.project_data),
                                       content_type='application/json')
        self.project_id = project_res.json['id']

    def register_user(self, user_data):
        self.client.post('/api/user/register/', data=json.dumps(user_data),
                         content_type='application/json')

    def test_create_task(self):
        """Tests creating a new task."""
        task_data = {"title": "New Task"}
        res = self.client.post(f'/api/projects/{self.project_id}/tasks/', headers=self.credentials,
                               data=json.dumps(task_data), content_type='application/json')
        self.assertEqual(res.status_code, 201)

    def test_create_task_missing_title(self):
        """Tests creating a task with missing title."""
        task_data = {}
        res = self.client.post(f'/api/projects/{self.project_id}/tasks/', headers=self.credentials,
                               data=json.dumps(task_data), content_type='application/json')
        self.assertEqual(res.status_code, 400)

    def test_get_tasks(self):
        """Tests getting a list of tasks."""
        task_data = {"title": "New Task"}
        self.client.post(f'/api/projects/{self.project_id}/tasks/', headers=self.credentials,
                         data=json.dumps(task_data), content_type='application/json')
        res = self.client.get(f'/api/projects/{self.project_id}/tasks/', headers=self.credentials)
        self.assertEqual(res.status_code, 200)
        self.assertGreater(len(res.json), 0)

    def test_get_task(self):
        """Tests getting a specific task."""
        task_data = {"title": "New Task"}
        task_res = self.client.post(f'/api/projects/{self.project_id}/tasks/',
                                    headers=self.credentials, data=json.dumps(task_data),
                                    content_type='application/json')
        task_id = task_res.json['id']
        res = self.client.get(f'/api/projects/{self.project_id}/tasks/{task_id}/',
                              headers=self.credentials)
        self.assertEqual(res.status_code, 200)

    def test_get_nonexistent_task(self):
        """Tests getting a task that doesn't exist."""
        res = self.client.get(f'/api/projects/{self.project_id}/tasks/9999/',
                              headers=self.credentials)
        self.assertEqual(res.status_code, 404)

    def test_update_task(self):
        """Tests updating a task."""
        task_data = {"title": "New Task"}
        task_res = self.client.post(f'/api/projects/{self.project_id}/tasks/',
                                    headers=self.credentials, data=json.dumps(task_data),
                                    content_type='application/json')
        task_id = task_res.json['id']
        updated_data = {"title": "Updated Task", "completed": 1}
        res = self.client.put(f'/api/projects/{self.project_id}/tasks/{task_id}/',
                              headers=self.credentials, data=json.dumps(updated_data),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertIn("Updated Task", res.get_data(as_text=True))
        self.assertIn('"completed":1', res.get_data(as_text=True))

    def test_update_task_invalid_fields(self):
        """Tests updating a task with invalid fields."""
        task_data = {"title": "New Task"}
        task_res = self.client.post(f'/api/projects/{self.project_id}/tasks/',
                                    headers=self.credentials, data=json.dumps(task_data),
                                    content_type='application/json')
        task_id = task_res.json['id']
        updated_data = {"invalid_field": "Invalid Data"}
        res = self.client.put(f'/api/projects/{self.project_id}/tasks/{task_id}/',
                              headers=self.credentials, data=json.dumps(updated_data),
                              content_type='application/json')
        self.assertEqual(res.status_code, 400)

    def test_update_task_partial(self):
        """Tests partially updating a task."""
        task_data = {"title": "New Task"}
        task_res = self.client.post(f'/api/projects/{self.project_id}/tasks/',
                                    headers=self.credentials, data=json.dumps(task_data),
                                    content_type='application/json')
        task_id = task_res.json['id']
        updated_data = {"completed": 1}
        res = self.client.put(f'/api/projects/{self.project_id}/tasks/{task_id}/',
                              headers=self.credentials, data=json.dumps(updated_data),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertIn('"completed":1', res.get_data(as_text=True))

    def test_delete_task(self):
        """Tests deleting a task."""
        task_data = {"title": "New Task"}
        task_res = self.client.post(f'/api/projects/{self.project_id}/tasks/',
                                    headers=self.credentials, data=json.dumps(task_data),
                                    content_type='application/json')
        task_id = task_res.json['id']
        res = self.client.delete(f'/api/projects/{self.project_id}/tasks/{task_id}/',
                                 headers=self.credentials)
        self.assertEqual(res.status_code, 204)

    def test_delete_nonexistent_task(self):
        """Tests deleting a task that doesn't exist."""
        res = self.client.delete(f'/api/projects/{self.project_id}/tasks/9999/',
                                 headers=self.credentials)
        self.assertEqual(res.status_code, 404)

    def test_get_task_wrong_user(self):
        """Tests getting a task with wrong user credentials."""
        task_data = {"title": "New Task"}
        task_res = self.client.post(f'/api/projects/{self.project_id}/tasks/',
                                    headers=self.credentials, data=json.dumps(task_data),
                                    content_type='application/json')
        task_id = task_res.json['id']
        wrong_credentials = auth_header('no-user', 'no-password')
        res = self.client.get(f'/api/projects/{self.project_id}/tasks/{task_id}/',
                              headers=wrong_credentials)
        self.assertEqual(res.status_code, 401)


class TestRateLimiter(TestBase):
    """Tests for the rate limiter."""

    def setUp(self):
        super().setUp()
        self.user_data = {
            "name": "John Doe", "email": "john@example.com", "username": "john", "password": "1234"}
        self.credentials = auth_header(self.user_data['username'], self.user_data['password'])
        self.register_user(**self.user_data)

    def register_user(self, **user_data):
        """Helper method to register a user."""
        return self.client.post('/api/user/register/', data=json.dumps(user_data),
                                content_type='application/json')

    def test_limiter(self):
        """Tests the rate limiter."""
        app.config['TESTING'] = False
        try:
            # First request should succeed
            res = self.client.get('/api/user/', headers=self.credentials)
            self.assertEqual(res.status_code, 200)

            # Second request should fail due to rate limit
            res = self.client.get('/api/user/', headers=self.credentials)
            self.assertEqual(res.status_code, 429)  # Too Many Requests
        finally:
            app.config['TESTING'] = True
