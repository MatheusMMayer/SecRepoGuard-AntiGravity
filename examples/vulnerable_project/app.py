# Projeto Vulnerável Fictício - Exemplo para teste do SecRepoGuard
import os

# Segredos expostos diretamente no código-fonte
API_KEY = "AIzaSyD-TEST-KEY-1234567890abcdef"
SECRET_KEY = "super_secret_session_token_key_goes_here!"
JWT_SECRET = "jwt_signing_secret_for_demo_purposes_only_xyz"

# URL de banco de dados expondo credenciais em texto plano
DATABASE_URL = "postgres://admin_user:SenhaForte123!@localhost:5432/prod_database"

def main():
    print("Iniciando aplicação...")
    print(f"Usando chave de API: {API_KEY}")
    
    # Token JWT exposto diretamente
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvYW8gU2lsdmEiLCJhZG1pbiI6dHJ1ZX0.v_Qy8B525Hh8e9_14W1t8V05yX1fA"
    print(f"Token de acesso: {access_token}")

if __name__ == "__main__":
    main()
