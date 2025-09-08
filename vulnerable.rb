require 'sinatra'
require 'sqlite3'

# 1. Hardcoded secret (CWE-798)
API_KEY = "supersecret1232"

# 2. SQL Injection (CWE-89)
get '/user' do
  username = params['username']
  db = SQLite3::Database.new "test.db"
  query = "SELECT * FROM users WHERE name = '#{username}'"  # ❌ vulnerable
  result = db.execute(query)
  result.to_s
end

# 3. Command Injection (CWE-78)
get '/ping' do
  host = params['host']
  output = `ping -c 1 #{host}`  # ❌ vulnerable
  output
end

# 4. Path Traversal (CWE-22)
get '/read' do
  file = params['file']
  content = File.read(file)  # ❌ vulnerable
  content
end

# 5. Cross-Site Scripting (CWE-79)
get '/greet' do
  name = params['name']
  "<h1>Hello #{name}</h1>"  # ❌ vulnerable
end

# 6. Insecure Deserialization (CWE-502)
get '/load' do
  data = params['data']
  obj = Marshal.load([data].pack("H*"))  # ❌ vulnerable
  obj.inspect
end

# 7. Open Redirect (CWE-601)
get '/redirect' do
  url = params['url']
  redirect url  # ❌ vulnerable
end

# 8. Information Exposure (CWE-200)
get '/debug' do
  ENV.to_h.to_s  # ❌ leaks sensitive env variables
end
