require 'sinatra'
require 'json'
require 'sqlite3'
require 'rack/cors'
require 'jwt'
require 'bcrypt'
require 'securerandom'
require 'date'

# CORS configuration (ouvert pour le moment)
use Rack::Cors do
  allow do
    origins '*' 
    resource '*', headers: :any, methods: [:get, :post, :put, :delete, :options]
  end
end

# Base de données SQLite
def dbc
  db = SQLite3::Database.new "data.db"
  db.results_as_hash = true 
  db
end

dbc.execute <<-SQL
  CREATE TABLE IF NOT EXISTS restaurants (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
  );
SQL

dbc.execute <<-SQL
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
SQL

# Clé secrète pour JWT (stockée de manière sécurisée en production)
SECRET_KEY = ENV['SECRET_KEY_BASE'] || SecureRandom.hex(64)

# Génération du token JWT avec expiration
def create_token(user_id)
  payload = {
    user_id: user_id,
    exp: (Time.now + 3600).to_i # Le token expire dans 1 heure
  }
  JWT.encode(payload, SECRET_KEY, 'HS256')
end

# Vérification du token JWT
def verify_token(token)
  begin
    decoded = JWT.decode(token, SECRET_KEY, true, { algorithm: 'HS256' })
    return decoded[0]['user_id'] if decoded[0]['exp'] > Time.now.to_i
  rescue JWT::DecodeError, JWT::ExpiredSignature
    return nil
  end
end

# Authentification par JWT
def authenticate!
  token = request.env['HTTP_AUTHORIZATION']&.split(' ')&.last
  user_id = verify_token(token)
  halt 401, { message: "Unauthorized" }.to_json unless user_id
  user_id
end

# Filtre pour définir le type de contenu
before do
  content_type :json
end

# Sanitize function for inputs (to prevent injections)
def sanitize(input)
  input.strip.gsub(/<|>|\"|\'/, '')
end

# Enregistrement d'un nouvel utilisateur
post '/register' do
  username = sanitize(params[:username])
  password = params[:password]

  halt 400, { message: "Username and password are required" }.to_json if username.empty? || password.nil?

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
  username = sanitize(params[:username])
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

# Ajout d'un nouveau restaurant (authentification requise)
post '/restaurant' do
  authenticate!
  name = sanitize(params[:name])

  halt 400, { message: "Name is required" }.to_json if name.empty?

  dbc.execute("INSERT INTO restaurants (name) VALUES (?)", name)
  status 201
  { message: "Restaurant added successfully" }.to_json
end

# Récupération d'un restaurant par son ID (authentification requise)
get '/restaurant/:id' do
  authenticate!
  id = params[:id].to_i
  restaurant = dbc.execute("SELECT * FROM restaurants WHERE id = ?", [id]).first

  if restaurant
    { restaurant: restaurant }.to_json
  else
    halt 404, { message: "Restaurant not found" }.to_json
  end
end

# Suppression d'un restaurant par son ID (authentification requise)
delete '/restaurant/:id' do
  authenticate!
  id = params[:id].to_i
  result = dbc.execute("DELETE FROM restaurants WHERE id = ?", [id])
  { message: "Restaurant deleted successfully" }.to_json
end

# Mise à jour d'un restaurant par son ID (authentification requise)
put '/restaurant/:id' do
  authenticate!
  id = params[:id].to_i
  name = sanitize(params[:name])

  halt 400, { message: "Name is required" }.to_json if name.empty?

  result = dbc.execute("UPDATE restaurants SET name = ? WHERE id = ?", [name, id])
  { message: "Restaurant updated successfully" }.to_json

end

# Gestion des routes inexistantes
not_found do
  content_type :json
  halt 404, { message: "Route not found" }.to_json
end
