require 'sinatra'
require 'sqlite3'

# Crée une méthode pour accéder à la base de données
def db_connection
  db = SQLite3::Database.new "test.db"
  db.results_as_hash = true # Retourne les résultats sous forme de hash
  db
end

# Crée la table si elle n'existe pas déjà
db_connection.execute <<-SQL
  CREATE TABLE IF NOT EXISTS restaurants (
    id INTEGER PRIMARY KEY,
    name TEXT
  );
SQL

# Route principale
get '/restaurants' do
  @restaurants = db_connection.execute("SELECT name FROM restaurants")
  erb :restaurants
end
