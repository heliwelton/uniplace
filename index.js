const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require ('express-session');
const app = express();
const port = 3001;

// Configuração do banco de dados
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Fernandes55',
    database: 'SALAS_UNIPLACE'
});

// Conectar ao banco de dados
db.connect((err) => {
    if (err) {
        console.error('Erro de conexão com o banco de dados: ' + err.stack);
        return;
    }
    console.log('Conectado ao banco de dados MySQL');
});

// Configuração do express para processar o corpo das requisições (body)
app.use(express.json());  // Garante que os dados serão processados como JSON
app.use(express.urlencoded({ extended: true }));  // Para lidar com dados de formulários tradicionais

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Erro ao tentar deslogar.');
        }
        res.redirect('/login?logout=true'); // Redireciona para login com o parâmetro 'logout=true'
    });
});

// Rota para buscar salas cadastradas
app.get('/salas', (req, res) => {
    db.query('SELECT * FROM SALAS', (err, results) => {
        if (err) {
            console.error('Erro ao buscar salas:', err);
            return res.status(500).send('Erro ao buscar salas');
        }
        res.json(results);  // Envia a lista de salas para o front-end
    });
});
//Verificar a disponibilidade da sala
app.get('/verificarDisponibilidade', (req, res) => {
    const { sala_id, data, hora_inicio, hora_fim } = req.query;

    if (!sala_id || !data || !hora_inicio || !hora_fim) {
        return res.status(400).json({ message: 'Parâmetros inválidos!' });
    }

    const query = `
        SELECT * FROM agendamentos 
        WHERE sala_id = ? 
        AND data = ? 
        AND (
            (hora_inicio < ? AND hora_fim > ?) OR
            (hora_inicio < ? AND hora_fim > ?)
        )
    `;
    db.query(query, [sala_id, data, hora_inicio, hora_inicio, hora_fim, hora_fim], (err, results) => {
        if (err) {
            console.error('Erro ao verificar disponibilidade:', err);
            return res.status(500).json({ message: 'Erro ao verificar disponibilidade.' });
        }

        if (results.length > 0) {
            return res.json({ disponivel: false });
        }
        res.json({ disponivel: true });
    });
});

// Rota para agendar uma sala
app.post('/agendamentos', (req, res) => {
   
    const { sala_id, data, hora_inicio, hora_fim } = req.body;
    const verificaDisponibilidadeQuery = `
    SELECT * FROM agendamentos 
    WHERE sala_id = ? 
    AND data = ? 
    AND NOT (hora_fim <= ? OR hora_inicio >= ?)
`;

db.query(verificaDisponibilidadeQuery, [sala_id, data, hora_inicio, hora_fim], (err, results) => {
    if (err) {
        console.error('Erro ao verificar disponibilidade:', err);
        return res.status(500).send('Erro ao verificar disponibilidade.');
    }

    if (results.length > 0) {
        return res.status(400).send('A sala já está ocupada nesse horário.');
    }

});

    const query = `
        INSERT INTO agendamentos (sala_id, data, hora_inicio, hora_fim) 
        VALUES (?, ?, ?, ?)`;

    db.query(query, [sala_id, data, hora_inicio, hora_fim], (err) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.status(201).send('Agendamento realizado com sucesso!');
    });
});

// Rota para a página de agendar sala
app.get('/professor/agendar_sala', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'agendar_sala.html'));
});

// Rota para a página de histórico de agendamentos
app.get('/professor/historico_agendamento', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'historico_agendamento.html'));
});

// Supomos que você tenha algum tipo de armazenamento para salas e professores.
// Exemplo usando arrays, mas você pode substituir isso por banco de dados.

let salas = [
    { numero: '101', reserva: '2024-11-20' },
    { numero: '202', reserva: '2024-11-21' },
    { numero: '103', reserva: '2024-11-22' }
];
let professores = [
    { nome: 'Professor A', departamento: 'Matemática' },
    { nome: 'Professor B', departamento: 'Física' }
];
let pendencias = [
    { descricao: 'Pendência 1', status: 'Aguardando aprovação' },
    { descricao: 'Pendência 2', status: 'Aguardando confirmação' },
    { descricao: 'Pendência 3', status: 'Aguardando documentação' }
];

// Rota para obter os agendamentos de uma sala (para o calendário)
app.get('/professor/obterAgendamentos', (req, res) => {
    const query = `
        SELECT 
            a.data, 
            a.hora_inicio, 
            a.hora_fim, 
            s.sala_id, 
            
        FROM agendamentos a
        JOIN salas s ON a.sala_id = s.id
        
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Erro ao buscar agendamentos:', err);
            return res.status(500).json({ message: 'Erro ao buscar agendamentos.' });
        }

        // Converte resultados para o formato esperado pelo FullCalendar
        const events = results.map(row => ({
            title: `${row.sala_id} `, // Corrigido: use crases para interpolação
            start: `${row.data}T${row.hora_inicio}`, // Corrigido: use crases para interpolação
            end: `${row.data}T${row.hora_fim}`, // Corrigido: use crases para interpolação
        }));

        res.json(events); // Retorna os eventos no formato JSON
    });
});


// Rota para listar os agendamentos
app.get('/agendamentos', (req, res) => {
    // Supondo que você tenha uma função que busca os agendamentos do banco de dados
    db.query('SELECT * FROM agendamentos', (err, results) => {
        if (err) {
            return res.status(500).send('Erro ao buscar agendamentos');
        }
        res.json(results);
    });
});

// Rota para cancelar um agendamento
app.delete('/agendamentos/:id', (req, res) => {
    const agendamentoId = req.params.id;
    db.query('UPDATE agendamentos SET cancelado = TRUE WHERE id = ?', [agendamentoId], (err, results) => {
        if (err) {
            return res.status(500).send('Erro ao cancelar o agendamento');
        }
        res.status(200).send('Agendamento cancelado com sucesso');
    });
});

// Rota para obter o número de salas cadastradas, professores, etc.
app.get('/admin/dados', (req, res) => {
    const salasCadastradas = salas.length;
    const professoresCadastrados = professores.length;
    
    // Suponhamos que o próximo evento seja o primeiro da lista de reservas
    const proximoEvento = salas[0] ? `Sala ${salas[0].numero} reservada em ${salas[0].reserva}` : 'Nenhum evento agendado';

    const proximosEventos = salas.map(sala => ({
        sala: sala.numero,
        data: sala.reserva
    }));

    res.json({
        salasCadastradas,
        professoresCadastrados,
        proximoEvento,
        pendencias: pendencias.length
    });
});

// Rota para exibir a página de cadastro de sala
app.get('/cadastrarSala', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'cadastrar_sala.html'));
});

// Rota para processar o cadastro de sala
app.post('/cadastrarSala', (req, res) => {
    const { nome, capacidade, tipo } = req.body;

    // Validação simples dos campos
    if (!nome || !capacidade || !tipo) {
        return res.status(400).send('Todos os campos são obrigatórios.');
    }

    // Inserção no banco de dados
    const query = `INSERT INTO Salas (nome, capacidade, tipo) VALUES (?, ?, ?)`;

    db.query(query, [nome, capacidade, tipo], (err) => {
        if (err) {
            console.error('Erro ao cadastrar sala:', err);
            return res.status(500).send('Erro ao cadastrar sala.');
        }
        res.status(201).send('Sala cadastrada com sucesso!');
    });
});

// Configuração de sessão
app.use(
    session({
        secret: 'chave-secreta', // Substitua por uma chave segura
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false }, // Altere para "true" com HTTPS
    })
);

// Configuração do Express para servir arquivos estáticos e processar requisições
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rota para a página de login
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Rota para a página de professor
app.get('/professor', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'professor.html'));
});
// Rota para a página de administração
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// Rota para a página de cadastrar professor
app.get('/cadastrarProfessor', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'cadastrar_professor.html'));
});

// Rota para processar o cadastro de professor
// Rota para processar o cadastro de professor
app.post('/cadastrarProfessor', async (req, res) => {
    try {
        const { nome, email, matricula, curso, senha } = req.body;

        // Verifica se todos os dados necessários foram fornecidos
        if (!nome || !email || !matricula || !curso || !senha) {
            return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
        }

        // Criptografa a senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(senha, saltRounds);

        // Insere o professor no banco de dados
        const query = `INSERT INTO professores (nome, email, matricula, curso, senha) 
                       VALUES (?, ?, ?, ?, ?)`;
        db.query(query, [nome, email, matricula, curso, hashedPassword], (err, results) => {
            if (err) {
                console.error('Erro ao cadastrar o professor:', err);
                return res.status(500).json({ message: 'Erro ao cadastrar o professor.' });
            }

            // Retorna uma resposta de sucesso
            res.status(201).json({ message: 'Professor cadastrado com sucesso!' });
        });
    } catch (error) {
        console.error('Erro ao processar o cadastro do professor:', error);
        res.status(500).json({ message: 'Erro interno ao processar a senha.' });
    }
});

app.post('/login', (req, res) => {
    const { matricula, senha, tipoUsuario } = req.body;

    // Verificar tipo de usuário e definir a consulta correta
    let query;
    let params = [matricula]; // Parâmetros para a consulta

    if (tipoUsuario === 'administrador') {
        query = 'SELECT * FROM administradores WHERE matricula = ?';
    } else if (tipoUsuario === 'professor') {
        query = 'SELECT * FROM professores WHERE matricula = ?'; // Sem "tipo_usuario"
    } else {
        return res.status(400).json({ message: 'Tipo de usuário inválido.' });
    }

    // Executa a consulta no banco de dados
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Erro ao verificar usuário no banco de dados:', err);
            return res.status(500).json({ message: 'Erro ao verificar usuário no banco de dados.' });
        }

        // Verificar se o usuário foi encontrado
        if (results.length === 0) {
            return res.status(401).json({ message: 'Usuário não encontrado ou dados inválidos.' });
        }

        const usuario = results[0];

        // Verificar a senha
        bcrypt.compare(senha, usuario.senha, (err, isMatch) => {
            if (err) {
                console.error('Erro ao verificar a senha:', err);
                return res.status(500).json({ message: 'Erro ao verificar a senha.' });
            }

            if (!isMatch) {
                return res.status(401).json({ message: 'Senha incorreta.' });
            }

            // Salvar o usuário na sessão
            req.session.usuario = usuario;

            // Redirecionar para a página de administração ou dashboard do professor
            if (tipoUsuario === 'administrador') {
                return res.json({ redirect: '/admin' });
            } else if (tipoUsuario === 'professor') {
                return res.json({ redirect: '/professor' });
            }
        });
    });
});

// Inicia o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
