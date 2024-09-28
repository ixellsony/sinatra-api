require 'sinatra'
require 'json'
require 'sqlite3'
require 'rack/cors'
require 'jwt'
require 'bcrypt'

use Rack::Cors do
  allow do
    origins '*' 
    resource '*', headers: :any, methods: [:get, :post, :put, :delete, :options]
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
  halt 401, { message: "Unauthorized" }.to_json unless user_id
  user_id
end

# Filtre avant chaque requête pour définir le type de contenu
before do
  content_type :json
end

# Enregistrement d'un nouvel utilisateur
post '/register' do
  username = params[:username]
  password = params[:password]
  
  if username.nil? || password.nil?
    halt 400, { message: "Username and password are required" }.to_json
  end
  
  password_hash = BCrypt::Password.create(password)
  
  begin
    dbc.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, password_hash])
    status 201
    { message: "User registered successfully" }.to_json
  rescue SQLite3::ConstraintException
    halt 409, { message: "Username already exists" }.to_json
  end
end

# Connexion utilisateur
post '/login' do
  username = params[:username]
  password = params[:password]
  
  user = dbc.execute("SELECT * FROM users WHERE username = ?", [username]).first
  
  if user && BCrypt::Password.new(user['password_hash']) == password
    token = create_token(user['id'])
    { token: token }.to_json
  else
    halt 401, { message: "Invalid username or password" }.to_json
  end
end

# Récupération de la liste des restaurants
get '/restaurants' do
  restaurants = dbc.execute("SELECT * FROM restaurants")
  { restaurants: restaurants }.to_json
end

# Ajout d'un nouveau restaurant
post '/restaurant' do
  authenticate!
  name = params[:name]
  
  if name.nil? || name.empty?
    halt 400, { message: "Name is required" }.to_json
  end

  dbc.execute("INSERT INTO restaurants (name) VALUES (?)", name)
  status 201
  { message: "Restaurant added successfully" }.to_json
end

# Récupération d'un restaurant par son ID
get '/restaurant/:id' do
  authenticate!
  id = params[:id]
  restaurant = dbc.execute("SELECT * FROM restaurants WHERE id = ?", [id]).first
  
  if restaurant
    { restaurant: restaurant }.to_json
  else
    halt 404, { message: "Restaurant not found" }.to_json
  end
end

# Suppression d'un restaurant par son ID
delete '/restaurant/:id' do
  authenticate!
  id = params[:id]
  result = dbc.execute("DELETE FROM restaurants WHERE id = ?", [id])
  
  if result.changes > 0
    { message: "Restaurant deleted successfully" }.to_json
  else
    halt 404, { message: "Restaurant not found" }.to_json
  end
end

# Mise à jour d'un restaurant par son ID
put '/restaurant/:id' do
  authenticate!
  id = params[:id]
  name = params[:name]

  if name.nil? || name.empty?
    halt 400, { message: "Name is required" }.to_json
  end

  result = dbc.execute("UPDATE restaurants SET name = ? WHERE id = ?", [name, id])
  
  if result.changes > 0
    { message: "Restaurant updated successfully" }.to_json
  else
    halt 404, { message: "Restaurant not found" }.to_json
  end
end

# Gestion des routes inexistantes
not_found do
  authenticate!
  content_type :json
  halt 404, { message: "Route not found" }.to_json
end