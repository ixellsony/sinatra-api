require 'sinatra'
require 'sqlite3'
require 'rack/cors'

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

get '/restaurants' do
  @restaurants = dbc.execute("SELECT name FROM restaurants")
  if @restaurants.any?
    erb :restaurants
  else
    "Aucun restaurant"
  end
end

post '/restaurant' do
  name = params[:name]
  dbc.execute("INSERT INTO restaurants (name) VALUES (?)", name)
  @restaurants = dbc.execute("SELECT name FROM restaurants")
  erb :restaurants
end

get '/restaurant/:id' do
  id = params[:id]
  @restaurant = dbc.execute("SELECT * FROM restaurants WHERE id = ?", id)
  if @restaurant.any?
    erb :restaurant
  else
    "Aucun restaurant avec cet id"
  end
end