from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

# Função para conectar ao banco de dados
def get_db_connection():
    conn = sqlite3.connect('hygge.db')
    conn.row_factory = sqlite3.Row
    return conn

# Rota para a página Home
@app.route('/home')
def home():
    return render_template('index.html')

# Rota principal que redireciona para home
@app.route('/')
def index():
    return redirect(url_for('home'))

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['senha'], password):
            session['username'] = user['nome']  # Salva o nome do usuário na sessão
            session['is_admin'] = user['is_admin']  # Salva o status de admin na sessão
            if user['is_admin']:
                return redirect(url_for('aulas_admin'))
            else:
                return redirect(url_for('aulas'))
        else:
            flash('Usuário ou senha incorretos.', 'error')
    
    return render_template('login.html')

# Rota para logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

# Rota para a página de edição de informações
@app.route('/editar_info')
def editar_info():
    return render_template('editar_info.html')

@app.route('/alterar_senha', methods=['POST'])
def alterar_senha():
    if 'username' not in session:
        flash('Você precisa estar logado para alterar a senha.', 'error')
        return redirect(url_for('login'))

    username = session['username']
    nova_senha = request.form['nova_senha']
    confirmar_senha = request.form['confirmar_senha']
    next_url = request.form.get('next', url_for('aulas'))

    if nova_senha != confirmar_senha:
        flash('A nova senha e a confirmação não coincidem.', 'error')
        return redirect(url_for('editar_info'))

    hashed_password = generate_password_hash(nova_senha)

    conn = get_db_connection()
    conn.execute('UPDATE usuarios SET senha = ? WHERE nome = ?', (hashed_password, username))
    conn.commit()
    conn.close()

    flash('Senha alterada com sucesso!', 'success')
    return redirect(next_url)

# Rota para cadastro
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        sexo = request.form['sexo']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('As senhas não coincidem!', 'error')
            return redirect(url_for('cadastro'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

        if user:
            flash('Este e-mail já está cadastrado.', 'error')
            conn.close()
            return redirect(url_for('cadastro'))

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO usuarios (nome, email, sexo, senha) VALUES (?, ?, ?, ?)', (nome, email, sexo, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Usuário cadastrado com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('cadastro.html')

# Rota para a página de aulas (admin)
@app.route('/aulas_admin')
def aulas_admin():
    username = session.get('username', 'Visitante')

    conn = get_db_connection()
    aulas = conn.execute('SELECT * FROM aulas').fetchall()
    conn.close()

    return render_template('aulas_admin.html', username=username, aulas=aulas)

# Rota para a página de aulas (usuário comum)
@app.route('/aulas')
def aulas():
    username = session.get('username', 'Visitante')

    conn = get_db_connection()
    user = conn.execute('SELECT is_admin FROM usuarios WHERE nome = ?', (username,)).fetchone()
    conn.close()

    if user and user['is_admin'] == 1:
        # Se o usuário é admin, redireciona para a página de administração
        return redirect(url_for('aulas_admin'))
    else:
        # Se não for admin, redireciona para a página de usuário
        conn = get_db_connection()
        aulas = conn.execute('SELECT * FROM aulas').fetchall()
        conn.close()
        return render_template('aulas.html', username=username, aulas=aulas)

# Rota para adicionar aula (apenas para administradores)
@app.route('/adicionar_aula', methods=['POST'])
def adicionar_aula():
    nome = request.form['nome']
    cor = request.form['cor']
    link = request.form['embed_code']
    conteudo = request.form['conteudo']
    numero = request.form['numero']

    conn = get_db_connection()
    conn.execute('INSERT INTO aulas (nome, cor, embed_code, conteudo, numero) VALUES (?, ?, ?, ?, ?)', (nome, cor, link, conteudo, numero))
    conn.commit()
    conn.close()

    flash('Aula adicionada com sucesso!', 'success')
    return redirect(url_for('aulas_admin'))

@app.route('/editar_aula', methods=['POST'])
def editar_aula():
    id_aula = request.form['id_aula']
    nome = request.form['nome']
    numero = request.form['numero']
    cor = request.form['cor']
    link = request.form['embed_code']
    conteudo = request.form['conteudo']
    
    conn = get_db_connection()
    conn.execute('UPDATE aulas SET nome = ?, numero = ?, cor = ?, embed_code = ?, conteudo = ? WHERE id_aula = ?',
                 (nome, numero, cor, link, conteudo, id_aula))
    conn.commit()
    conn.close()
    
    return redirect(url_for('aulas_admin'))

@app.route('/deletar_aula/<int:id_aula>', methods=['POST'])
def deletar_aula(id_aula):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Deletar aula
    cursor.execute('DELETE FROM aulas WHERE id_aula = ?', (id_aula,))
    
    conn.commit()
    conn.close()
    
    flash('Aula deletada com sucesso!', 'success')
    return redirect(url_for('aulas_admin'))  # Redirecionar para a página de administração de aulas

# Rota para a página de detalhes da aula
@app.route('/aula/<int:id_aula>')
def aula_detail(id_aula):
    conn = get_db_connection()
    aula = conn.execute('SELECT * FROM aulas WHERE id_aula = ?', (id_aula,)).fetchone()
    conn.close()
    
    if aula is None:
        return "Aula não encontrada", 404

    # Obtém o nome do usuário da sessão
    username = session.get('username', 'Visitante')

    return render_template('aula_detail.html', aula=aula, username=username)

@app.route('/exercicios')
def exercicios():
    username = session.get('username', 'Visitante')

    conn = get_db_connection()
    user = conn.execute('SELECT is_admin FROM usuarios WHERE nome = ?', (username,)).fetchone()

    # Consulta os exercícios disponíveis
    exercicios = conn.execute('SELECT e.*, a.cor FROM exercicios e JOIN aulas a ON e.id_aula = a.id_aula').fetchall()
    conn.close()

    if user and user['is_admin'] == 1:
        return redirect(url_for('exercicios_admin'))
    else:
        return render_template('exercicios.html', username=username, exercicios=exercicios)

# Rota para a página de exercícios (admin)
@app.route('/exercicios_admin')
def exercicios_admin():
    username = session.get('username', 'Visitante')
    
    conn = get_db_connection()
    exercicios = conn.execute('SELECT * FROM exercicios').fetchall()
    aulas = conn.execute('SELECT * FROM aulas').fetchall()
    conn.close()

    return render_template('exercicios_admin.html', username=username, exercicios=exercicios, aulas=aulas)

# Rota para adicionar exercício
@app.route('/adicionar_exercicio', methods=['POST'])
def adicionar_exercicio():
    id_aula = request.form['id_aula']
    nome = request.form['nome']
    
    # Obtemos a cor da aula correspondente
    conn = get_db_connection()
    aula = conn.execute('SELECT cor FROM aulas WHERE id_aula = ?', (id_aula,)).fetchone()
    cor = aula['cor'] if aula else None

    # Adicionamos o exercício com a cor correspondente
    conn.execute('INSERT INTO exercicios (id_aula, nome, cor) VALUES (?, ?, ?)', (id_aula, nome, cor))
    exercicio_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]  # Obtém o ID do exercício recém-adicionado

    # Obter as perguntas e alternativas
    perguntas = request.form.getlist('pergunta[]')
    alternativas = request.form.getlist('alternativa[]')
    corretas = request.form.getlist('correta[]')

    cursor = conn.cursor() 
    alternativa_index = 0  # Índice para rastrear alternativas

    for i, pergunta in enumerate(perguntas):
        cursor.execute('INSERT INTO perguntas (nome, id_exercicio) VALUES (?, ?)', (pergunta, exercicio_id))
        pergunta_id = cursor.lastrowid  # Obtém o ID da pergunta recém-adicionada

        # Adicionar as alternativas correspondentes à pergunta
        for j in range(4):
            alternativa = alternativas[alternativa_index]
            correta = 'S' if str(j + 1) == corretas[i] else 'N'
            cursor.execute('INSERT INTO alternativas (nome, correta, id_pergunta) VALUES (?, ?, ?)',
                           (alternativa, correta, pergunta_id))
            alternativa_index += 1  # Avança o índice para a próxima alternativa

    conn.commit()
    conn.close()
    
    return redirect(url_for('exercicios_admin'))

# Rota para editar exercício
@app.route('/editar_exercicio', methods=['POST'])
def editar_exercicio():
    id_exercicio = request.form['id_exercicio']
    nome = request.form['nome']
    id_aula = request.form['id_aula']
    
    # Atualizando o exercício no banco de dados
    conn = get_db_connection()
    conn.execute('UPDATE exercicios SET nome = ?, id_aula = ? WHERE id_exercicio = ?', (nome, id_aula, id_exercicio))
    conn.commit()

    # Atualizando a cor do exercício com base na aula associada
    aula = conn.execute('SELECT cor FROM aulas WHERE id_aula = ?', (id_aula,)).fetchone()
    if aula:
        conn.execute('UPDATE exercicios SET cor = ? WHERE id_exercicio = ?', (aula['cor'], id_exercicio))
        conn.commit()

    conn.close()

    flash('Exercício atualizado com sucesso!', 'success')
    return redirect(url_for('exercicios_admin'))

# Rota para excluir exercício
@app.route('/deletar_exercicio/<int:id_exercicio>', methods=['POST'])
def deletar_exercicio(id_exercicio):
    conn = get_db_connection()

    try:
        # Excluir as alternativas associadas às perguntas do exercício
        conn.execute('DELETE FROM alternativas WHERE id_pergunta IN (SELECT id_pergunta FROM perguntas WHERE id_exercicio = ?)', (id_exercicio,))
        
        # Excluir as perguntas associadas ao exercício
        conn.execute('DELETE FROM perguntas WHERE id_exercicio = ?', (id_exercicio,))
        
        # Excluir o exercício
        conn.execute('DELETE FROM exercicios WHERE id_exercicio = ?', (id_exercicio,))
        
        conn.commit()

    except sqlite3.Error as e:
        flash(f'Erro ao excluir o exercício: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('exercicios_admin'))

# Rota para a pagina das perguntas
@app.route('/exercicio_detail/<int:id_exercicio>')
def exercicio_detail(id_exercicio):
    username = session.get('username', 'Visitante')
    conn = get_db_connection()

    # Obter o exercício
    exercicio = conn.execute('SELECT * FROM exercicios WHERE id_exercicio = ?', (id_exercicio,)).fetchone()
    if exercicio is None:
        flash('Exercício não encontrado!', 'danger')
        return redirect(url_for('exercicios'))

    # Obter perguntas e alternativas
    perguntas = conn.execute('SELECT * FROM perguntas WHERE id_exercicio = ?', (id_exercicio,)).fetchall()
    alternativas = {
        pergunta['id_pergunta']: conn.execute('SELECT * FROM alternativas WHERE id_pergunta = ?', (pergunta['id_pergunta'],)).fetchall()
        for pergunta in perguntas
    }

    conn.close()
    return render_template('exercicio_detail.html', username=username, exercicio=exercicio, perguntas=perguntas, alternativas=alternativas)

@app.route('/submit_respostas/<int:id_exercicio>', methods=['POST'])
def submit_respostas(id_exercicio):
    username = session.get('username', 'Visitante')
    conn = get_db_connection()

    # Obter as perguntas do exercício
    perguntas = conn.execute('SELECT * FROM perguntas WHERE id_exercicio = ?', (id_exercicio,)).fetchall()

    resultados = {}
    total_perguntas = len(perguntas)
    acertos = 0

    for pergunta in perguntas:
        id_pergunta = pergunta['id_pergunta']
        resposta_usuario = request.form.get(f'pergunta_{id_pergunta}')

        # Verificar se a alternativa enviada é correta
        alternativa_correta = conn.execute(
            'SELECT id_alternativa FROM alternativas WHERE id_pergunta = ? AND correta = "S"',
            (id_pergunta,)
        ).fetchone()

        if alternativa_correta and resposta_usuario == str(alternativa_correta['id_alternativa']):
            resultados[id_pergunta] = 'correta'
            acertos += 1
        else:
            resultados[id_pergunta] = 'incorreta'

    # Obter todas as alternativas pra exibição
    alternativas = {
        pergunta['id_pergunta']: conn.execute('SELECT * FROM alternativas WHERE id_pergunta = ?', (pergunta['id_pergunta'],)).fetchall()
        for pergunta in perguntas
    }

    conn.close()

    # Renderizar a mesma página c os resultados
    return render_template(
        'exercicio_detail.html',
        username=username,
        exercicio={'id_exercicio': id_exercicio, 'nome': f'Exercício {id_exercicio}'},
        perguntas=perguntas,
        alternativas=alternativas,
        resultados=resultados,
        total_perguntas=total_perguntas,
        acertos=acertos
    )

# Rota para a página de explorar
@app.route('/explorar')
def explorar():
    username = session.get('username', 'Visitante')
    return render_template('explorar.html', username=username)

if __name__ == '__main__':
    app.run(debug=True)