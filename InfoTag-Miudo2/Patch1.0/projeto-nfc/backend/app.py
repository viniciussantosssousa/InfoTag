import firebase_admin
from firebase_admin import credentials, firestore, auth
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt

# --- 1. Configuração Inicial ---
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# Inicializa o Firebase Admin
cred = credentials.Certificate('serviceAccountKey.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

# --- 2. Rotas Públicas (Portal do Paciente) ---
# (Suas rotas /api/public-info e /api/unlock continuam aqui, sem alterações)

@app.route('/api/public-info/<string:user_id>', methods=['GET'])
def get_public_info(user_id):
    try:
        user_ref = db.collection('usuarios').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        user_data = user_doc.to_dict()
        public_info = user_data.get('infoPublica', {})
        return jsonify(public_info), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unlock', methods=['POST'])
def unlock_data():
    try:
        data = request.get_json()
        user_id = data.get('userId')
        pin_fornecido = data.get('pin')
        if not user_id or not pin_fornecido:
            return jsonify({'success': False, 'error': 'Faltando dados'}), 400
        user_ref = db.collection('usuarios').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404
        user_data = user_doc.to_dict()
        pin_hash_armazenado = user_data.get('seguranca', {}).get('pinHash')
        if not pin_hash_armazenado:
             return jsonify({'success': False, 'error': 'Usuário sem PIN'}), 500
        if bcrypt.checkpw(pin_fornecido.encode('utf-8'), pin_hash_armazenado.encode('utf-8')):
            private_data = user_data.get('infoPrivada', {})
            return jsonify({'success': True, 'data': private_data}), 200
        else:
            return jsonify({'success': False, 'error': 'PIN inválido'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- 3. Rotas do Dashboard (Seguras) ---

# Função helper para verificar o token do Firebase
def check_auth(request):
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None
        id_token = auth_header.split('Bearer ')[1]
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        print(f"Erro de autenticação: {e}")
        return None

# --- Rota de LEITURA (Read All) ---
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    admin_user = check_auth(request)
    if not admin_user:
        return jsonify({'error': 'Não autorizado'}), 401
    
    try:
        users_ref = db.collection('usuarios')
        users_docs = users_ref.stream()
        users_list = []
        for doc in users_docs:
            user_data = doc.to_dict()
            user_data['id'] = doc.id 
            users_list.append(user_data)
        return jsonify(users_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Rota de LEITURA (Read One) ---
@app.route('/api/admin/user/<string:user_id>', methods=['GET'])
def get_user(user_id):
    admin_user = check_auth(request)
    if not admin_user:
        return jsonify({'error': 'Não autorizado'}), 401
    
    try:
        user_ref = db.collection('usuarios').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        return jsonify(user_doc.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Rota de CRIAÇÃO (Create) ---
@app.route('/api/admin/create-user', methods=['POST'])
def create_user():
    admin_user = check_auth(request)
    if not admin_user:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        data = request.get_json()
        pin_texto_puro = data.get('pin')
        
        if not pin_texto_puro:
             return jsonify({'success': False, 'error': 'O PIN é obrigatório'}), 400

        # Gera o hash do PIN
        pin_bytes = pin_texto_puro.encode('utf-8')
        salt = bcrypt.gensalt()
        pin_hash = bcrypt.hashpw(pin_bytes, salt).decode('utf-8')

        # Monta o documento com a estrutura correta
        new_user_data = {
            "infoPublica": data.get('infoPublica', {}),
            "infoPrivada": data.get('infoPrivada', {}),
            "seguranca": {
                "pinHash": pin_hash
            }
        }
        
        # Salva no Firestore (ele gera um ID automático)
        doc_ref = db.collection('usuarios').document()
        doc_ref.set(new_user_data)
        
        return jsonify({'success': True, 'newUserId': doc_ref.id}), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- Rota de ATUALIZAÇÃO (Update) ---
@app.route('/api/admin/user/<string:user_id>', methods=['PUT'])
def update_user(user_id):
    admin_user = check_auth(request)
    if not admin_user:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        data = request.get_json()
        user_ref = db.collection('usuarios').document(user_id)

        # Monta os dados para atualização
        update_data = {
            "infoPublica": data.get('infoPublica', {}),
            "infoPrivada": data.get('infoPrivada', {})
        }
        
        # IMPORTANTE: Só atualiza o PIN se um novo for fornecido
        pin_texto_puro = data.get('pin')
        if pin_texto_puro: # Se o campo PIN não está vazio
            pin_bytes = pin_texto_puro.encode('utf-8')
            salt = bcrypt.gensalt()
            pin_hash = bcrypt.hashpw(pin_bytes, salt).decode('utf-8')
            update_data["seguranca"] = {"pinHash": pin_hash}
        
        # O 'merge=True' garante que só os campos enviados serão atualizados
        user_ref.set(update_data, merge=True)
        
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- Rota de DELEÇÃO (Delete) ---
@app.route('/api/admin/user/<string:user_id>', methods=['DELETE'])
def delete_user(user_id):
    admin_user = check_auth(request)
    if not admin_user:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        user_ref = db.collection('usuarios').document(user_id)
        user_ref.delete()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- 4. Roda o servidor ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)