import requests

username = 'user'
password = 's3cretP4ssword'

# response = requests.get('http://localhost:5000', params={'username': username, 'password': password})
response = requests.post('http://localhost:5000', json={'username': username, 'password': password})
print('Response from server:', response.text)
