from Intranet import database, login_manager
from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from flask_login import UserMixin


@login_manager.user_loader
def load_usuario(id_usuario):
    return Usuarios.query.get(int(id_usuario))


class Situacoes(database.Model, UserMixin):
    __tablename__ = 'situacoes'
    id = database.Column(database.Integer, primary_key=True)
    nome_situacao = database.Column(database.String(100), unique=True)


class Setores(database.Model):
    __tablename__ = 'setores'
    id = database.Column(database.Integer, primary_key=True)
    nome_setor = database.Column(database.String(100), nullable=False)
    hierarquia = database.Column(database.Integer) # 0=Operacional 1=Direção 2=Usuario admin
    icone = database.Column(database.String)
    usuarios = database.relationship('Usuarios', backref='usuarios_setor', lazy=True)

    def __str__(self):
        return self.nome_setor


class Cargos(database.Model):
    __tablename__ = 'cargos'
    id = database.Column(database.Integer, primary_key=True)
    nome_cargo = database.Column(database.String, nullable=False)
    grau_hierarquia = database.Column(database.Integer, nullable=False, unique=True)
    usuarios = database.relationship('Usuarios', backref='cargo_usuario', lazy=True)

    def __str__(self):
        return self.nome_cargo


class Ramais(database.Model):
    __tablename__ = 'ramais'
    id = database.Column(database.Integer, primary_key=True)
    ramal = database.Column(database.String(10), nullable=False, unique=True)
    situacoes_ramais = database.Column(database.Integer, database.ForeignKey('situacoes.id', ondelete='CASCADE'), default=1)

    def __str__(self):
        return self.ramal


class TopicosCentralSoucoes(database.Model):
    __tablename__ = 'topicos_central_solucoes'
    id = database.Column(database.Integer, primary_key=True)
    nome_topico = database.Column(database.String(50))
    observacao = database.Column(database.Text)
    setor = database.Column(database.Integer, database.ForeignKey('setores.id', ondelete='CASCADE'))
    situacao = database.Column(database.Integer, database.ForeignKey('situacoes.id', ondelete='CASCADE'), default=1)
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class Tipos_recados(database.Model):
    __tablename__ = 'tipos_recados'
    id = database.Column(database.Integer, primary_key=True)
    nome_tipo_recado = database.Column(database.String(50), unique=True, nullable=False)
    classe_html = database.Column(database.String(50), unique=True)
    observacao = database.Column(database.String(200))
    situacao = database.Column(database.Integer, database.ForeignKey('situacoes.id', ondelete='CASCADE'), default=1)
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class Usuarios(database.Model, UserMixin):
    __tablename__ = 'usuarios'
    id = database.Column(database.Integer, primary_key=True)
    nome_usuario = database.Column(database.String(100), nullable=False)
    username = database.Column(database.String(100), nullable=False, unique=True)
    email_pessoal = database.Column(database.String(100), unique=True, nullable=False)
    email_uso = database.Column(database.String(100), nullable=False)
    senha = database.Column(database.String(150), nullable=False)
    id_setor = database.Column(database.Integer, database.ForeignKey('setores.id', ondelete='CASCADE'))
    id_cargo = database.Column(database.Integer, database.ForeignKey('cargos.id', ondelete='CASCADE'))
    situacao_usuario = database.Column(database.Integer, database.ForeignKey('situacoes.id', ondelete='CASCADE'), default=1)
    data_cadastro = database.Column(database.DateTime)


class UsuarioRamal(database.Model):
    __tablename__ = 'usuarios_ramais'
    id = database.Column(database.Integer, primary_key=True)
    id_usuario = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'), unique=True)
    id_ramal = database.Column(database.Integer, database.ForeignKey('ramais.id', ondelete='CASCADE'))
    database.UniqueConstraint('id_usuario', 'id_ramal', name='uq_usuario_ramal')
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class EdicaoPerfil(database.Model):
    __tablename__ = 'edicao_perfil'
    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.String(100))
    nome_usuario = database.Column(database.String(100))
    email_uso = database.Column(database.String(100))
    email_pessoal = database.Column(database.String(100))
    id_cargo = database.Column(database.Integer)
    situacao_usuario = database.Column(database.Integer)
    id_setor = database.Column(database.Integer)
    id_ramal = database.Column(database.Integer)
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))


class IdentificadorPostagens(database.Model):
    __tablename__ = 'identificador_postagens'
    id = database.Column(database.Integer, primary_key=True)
    nome_identificador = database.Column(database.String(50), nullable=False)
    observacao = database.Column(database.String(200))
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class Posts(database.Model):
    __tablename__ = 'posts'
    id = database.Column(database.Integer, primary_key=True)
    identificador = database.Column(database.Integer, database.ForeignKey('identificador_postagens.id', ondelete='CASCADE'))
    titulo = database.Column(database.String(100), nullable=False)
    body = database.Column(database.Text, nullable=False)
    data_inicio = database.Column(database.DateTime)
    data_fim = database.Column(database.DateTime)
    data_cadastro = database.Column(database.DateTime)
    visivel = database.Column(database.Integer) #1 VIsivel para todos, 2 visivel para cargos iguais ou acima, 3 para o cargo do setor
    cargo = database.Column(database.Integer, database.ForeignKey('cargos.id', ondelete='CASCADE'))
    setor = database.Column(database.Integer, database.ForeignKey('setores.id', ondelete='CASCADE'))
    id_topico = database.Column(database.Integer, database.ForeignKey('topicos_central_solucoes.id', ondelete='CASCADE'))
    id_usuario_destino = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    id_tipo_recado = database.Column(database.Integer, database.ForeignKey('tipos_recados.id', ondelete='CASCADE'))
    id_usuario_autor = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    views = database.Column(database.Integer)


class SituacoesSuporte(database.Model):
    __tablename__ = 'situacoes_suporte'
    id = database.Column(database.Integer, primary_key=True)
    nome_situacao_suporte = database.Column(database.String(100), nullable=False)
    classe_html = database.Column(database.String(50), unique=True)
    visualizacao = database.Column(database.Integer) #1 - usuario ultimo tramite pode responder
    # 2- usuario ultimo tramite não pode responder
    # 3- todos podem responder 4 - usuario_destino pode responder, 5 - usuario_autor pode responder
    situacao = database.Column(database.Integer, database.ForeignKey('situacoes.id', ondelete='CASCADE'), default=1)
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class TiposSuporte(database.Model):
    __tablename__ = 'tipos_suporte'
    id = database.Column(database.Integer, primary_key=True)
    nome_tipo_suporte = database.Column(database.String(100), nullable=False, unique=True)
    situacao = database.Column(database.Integer, database.ForeignKey('situacoes.id', ondelete='CASCADE'), default=1)
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class TramitesSuporte(database.Model):
    __tablename__ = 'tramites_suporte'
    id = database.Column(database.Integer, primary_key=True)
    id_suporte = database.Column(database.Integer, database.ForeignKey('suporte.id', ondelete='CASCADE'))
    id_secundario = database.Column(database.Integer)
    body_tramite = database.Column(database.Text)
    id_autor = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    id_situacao_tramite = database.Column(database.Integer, database.ForeignKey('situacoes_suporte.id', ondelete='CASCADE'))
    ocultar = database.Column(database.Integer) #1- visivel 0- Oculto
    data_cadastro = database.Column(database.DateTime)

    def as_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

    def from_dict(self, data):
        for key, value in data.items():
            setattr(self, key, value)


class GrauUrgencia(database.Model):
    __tablename__ = 'grau_urgencia'
    id = database.Column(database.Integer, primary_key=True)
    nome_urgencia = database.Column(database.String(50), nullable=False)
    id_usuario_cadastro = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime)


class Suporte(database.Model):
    __tablename__ = 'suporte'
    id = database.Column(database.Integer, primary_key=True)
    id_tipo_suporte = database.Column(database.Integer, database.ForeignKey('tipos_suporte.id', ondelete='CASCADE'))
    titulo_suporte = database.Column(database.String(100), nullable=False, unique=True)
    id_setor_suporte = database.Column(database.Integer, database.ForeignKey('setores.id', ondelete='CASCADE'))
    id_usuario_autor = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    id_usuario_destino = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    id_setor_destino_suporte = database.Column(database.Integer, database.ForeignKey('setores.id', ondelete='CASCADE'))
    id_ultimo_tramite = database.Column(database.Integer) # tramites_suporte.id
    id_situacao_suporte = database.Column(database.Integer, database.ForeignKey('situacoes_suporte.id', ondelete='CASCADE'))
    id_grau_urgencia = database.Column(database.Integer, database.ForeignKey('grau_urgencia.id', ondelete='CASCADE'))
    data_cadastro = database.Column(database.DateTime, default=datetime.now())
    data_ultimo_tramite = database.Column(database.DateTime)
    data_prazo = database.Column(database.DateTime)
    ordem_fila = database.Column(database.Integer)
    visivel = database.Column(database.Integer) #1- visivel 0- Oculto
    resposta = database.Column(database.Integer) # situacoes_suporte.visualizacao
    observacao = database.Column(database.Text)

    def as_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

    def from_dict(self, data):
        if data is not None:
            for key, value in data.items():
                if hasattr(self, key):
                    setattr(self, key, value)
        return self


class VisualizacaoCentralSolucoes(database.Model):
    __tablename__ = 'visualizacao_central_solucoes'
    id = database.Column(database.Integer, primary_key=True)
    id_postagens = database.Column(database.Integer, database.ForeignKey('posts.id', ondelete='CASCADE'))
    id_usuario = database.Column(database.Integer, database.ForeignKey('usuarios.id', ondelete='CASCADE'))
    data_viz = database.Column(database.DateTime)


class Auditoria(database.Model):
    __tablename__ = 'auditoria'
    id = database.Column(database.Integer, primary_key=True)
    table_name = database.Column(database.String(255))
    operation = database.Column(database.String(10))
    old_data = database.Column(database.JSON)
    new_data = database.Column(database.JSON)
    timestamp = database.Column(database.DateTime, default=database.func.now())


class RegistroLogin(database.Model):
    __tablename__ = 'registro_login'
    id = database.Column(database.Integer, primary_key=True)
    usuario_id = database.Column(database.Integer, database.ForeignKey('usuarios.id'), nullable=False)
    data_login = database.Column(database.DateTime, nullable=False, default=datetime.now)
    data_logout = database.Column(database.DateTime)