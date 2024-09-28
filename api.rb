require 'sinatra'
require 'sqlite3'
require 'rack/cors'
require 'jwt'
require 'bcrypt'

use Rack::Cors do
  allow do
    origins '*' 
    resource '*', headers: :any, methods: [:get, :post, :options]
  end
end

def dbc
  db = SQLite3::Database.new "data.db"
  db.results_as_hash = true 
  db
end

dbc.execute <<-SQL
  CREATE TABLE IF NOT EXISTS restaurants (
    id INTEGER PRIMARY KEY,
    name TEXT
  );
SQL

dbc.execute <<-SQL
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT
  );
SQL

SECRET_KEY = 'your_secret_key_here'

def create_token(user_id)
  payload = { user_id: user_id }
  JWT.encode(payload, SECRET_KEY, 'HS256')
end

def verify_token(token)
  begin
    decoded = JWT.decode(token, SECRET_KEY, true, { algorithm: 'HS256' })
    return decoded[0]['user_id']
  rescue JWT::DecodeError
    return nil
  end
end

def authenticate!
  token = request.env['HTTP_AUTHORIZATION']&.split(' ')&.last
  user_id = verify_token(token)
  halt 401, "Unauthorized" unless user_id
  user_id
end

def optionally_authenticate
  token = request.env['HTTP_AUTHORIZATION']&.split(' ')&.last
  verify_token(token) if token
end

post '/register' do
  username = params[:username]
  password = params[:password]
  
  if username.nil? || password.nil?
    return "Username and password are required"
  end
  
  password_hash = BCrypt::Password.create(password)
  
  begin
    dbc.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, password_hash])
    "User registered successfully"
  rescue SQLite3::ConstraintException
    "Username already exists"
  end
end

post '/login' do
  username = params[:username]
  password = params[:password]
  
  user = dbc.execute("SELECT * FROM users WHERE username = ?", [username]).first
  
  if user && BCrypt::Password.new(user['password_hash']) == password
    token = create_token(user['id'])
    { token: token }.to_json
  else
    "Invalid username or password"
  end
end

get '/restaurants' do
  authenticate!
  @restaurants = dbc.execute("SELECT name FROM restaurants")
  if @restaurants.any?
    erb :restaurants
  else
    "Aucun restaurant"
  end
end

post '/restaurant' do
  authenticate!
  name = params[:name]
  dbc.execute("INSERT INTO restaurants (name) VALUES (?)", name)
  @restaurants = dbc.execute("SELECT name FROM restaurants")
  erb :restaurants
end

get '/restaurant/:id' do
  authenticate!
  id = params[:id]
  @restaurant = dbc.execute("SELECT * FROM restaurants WHERE id = ?", id)
  if @restaurant.any?
    erb :restaurant
  else
    "Aucun restaurant avec cet id"
  end
end
