from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, DateTimeField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user
from wtforms_alchemy import QuerySelectField
from Intranet.models import Usuarios
from flask_ckeditor import CKEditorField


class FormCriarConta(FlaskForm):
    nome_usuario = StringField('Nome Usuário:', validators=[DataRequired(message='Favor inserir nome'), Length(5, 100)])
    username = StringField('Username:', validators=[DataRequired(message='Favor inserir username'), Length(5, 100)])
    email_pessoal = StringField('E-mail Pessoal:', validators=[DataRequired(message='Favor inserir e-mail pessoal'), Email()])
    email_uso = StringField('E-mail Uso:', validators=[DataRequired(message='Favor inserir e-mail de uso'), Email()])
    id_cargo = SelectField('Cargo:')
    id_setor = SelectField('Setor:')
    senha = PasswordField('Senha:', validators=[DataRequired(message='Por favor preencha a senha'), Length(8, 150)])
    confirmacao_senha = PasswordField('Confirme sua senha:', validators=[DataRequired(), EqualTo('senha', message='Senhas precisam ser iguais')])
    botao_submit = SubmitField('Criar conta')

    def validate_email(self, email):
        usuario = Usuarios.query.filter_by(email=email.data).first()
        if usuario:
            raise ValidationError('E-mail já cadastrado!')


class FormLogin(FlaskForm):
    email = StringField('E-mail:', validators=[DataRequired(message='Por favor, insira um email.'),
                                               Email('Por favor, insira um email válido.')])
    senha = PasswordField('Senha:',
                          validators=[DataRequired(message='Por favor digite uma senha.'),
                                      Length(8, 100)])
    lembrar_dados = BooleanField("Manter logado")
    botao_submit_login = SubmitField('Fazer login')


class FormCadastroRamais(FlaskForm):
    ramal = StringField('Ramal', validators=[DataRequired(), Length(min=3, max=5)])
    situacoes_ramais = SelectField('Situação')
    botao_submit = SubmitField('Cadastrar')


class FormVinculoRamais(FlaskForm):
    id_usuario = SelectField('Usuario')
    id_ramal = SelectField('Ramal')
    botao_submit = SubmitField('Cadastrar')


class FormEdicaoPerfil(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Favor inserir username')])
    nome_usuario = StringField('Nome Usuário', validators=[DataRequired(message='Favor inserir nome usuário')])
    email_uso = StringField('E-mail uso', validators=[DataRequired(message='Por favor, insira um email.'),
                                               Email('Por favor, insira um email válido.')])
    email_pessoal = StringField('E-mail pessoal', validators=[DataRequired(message='Por favor, insira um email.'),
                                                      Email('Por favor, insira um email válido.')])
    id_cargo = SelectField('Cargo')
    id_setor = SelectField('Setor')
    id_ramal = SelectField('Ramal')
    situacao_usuario = SelectField('Situação cadastro')
    botao_submit = SubmitField('Cadastrar')


class FormRecadosFixo(FlaskForm):
    titulo = StringField('Título Publicação', validators=[DataRequired(message='Necessário inserir título')])
    body = CKEditorField('Recado')
    setor = SelectField('Setor:')
    cargo = SelectField('Cargos')
    id_usuario_destino = SelectField('Usuario Destino')
    botao_submit_postar = SubmitField('postar', name='postar')


class FormEditarRecadosFixo(FlaskForm):
    titulo = StringField('Título Publicação', validators=[DataRequired(message='Necessário inserir título')])
    body = CKEditorField('Recado',
                         validators=[DataRequired(message='Necessário inserir recado')])
    setor = SelectField('Setor:')
    cargo = SelectField('Cargos')
    id_usuario_destino = SelectField('Usuario Destino')
    botao_submit_temporario = SubmitField('Temporário', name='temporario')
    botao_submit_postar = SubmitField('Editar', name='editar')


class FormTiposSuporte(FlaskForm):
    nome_tipo_suporte = StringField('Nome tipo suporte', validators=[DataRequired(message='Necessário inserir título')])
    botao_submit = SubmitField('Cadastrar')


class FormTramitesSuporte(FlaskForm):
    body_tramite = CKEditorField('Explicação',
                         validators=[DataRequired(message='Necessário inserir texto')])
    ocultar = BooleanField('Ocultar trâmite')


class FormTramitesSuporteResposta(FlaskForm):
    body_tramite = CKEditorField('Resposta', validators=[DataRequired(message='Favor inserir texto')])
    ocultar = BooleanField('Ocultar trâmite')
    encerrar = SelectField('Tipo Resposta')
    botao_submit = SubmitField('cadastrar')


class FormEncaminharSuporte(FlaskForm):
    usuarios = SelectField('Encaminhar para:')
    botao_submit = SubmitField('Encaminhar')


class FormSuporte(FlaskForm):
    id_tipo_suporte = SelectField('Tipo Suporte')
    titulo_suporte = StringField('Título Suporte', validators=[DataRequired(message='Necessário inserir título')])
    id_setor_suporte = SelectField('Setor Suporte')
    id_usuario_destino = SelectField('Usuário Destino')
    id_setor_destino_suporte = SelectField('Setor Destino')
    id_grau_urgencia = SelectField('Grau Urgência')
    observacao = CKEditorField('Explicação')
    body_tramite = CKEditorField('Explicação',
                                 validators=[DataRequired(message='Necessário inserir texto')])
    ocultar = BooleanField('Ocultar trâmite')
    botao_submit = SubmitField('Cadastrar')


class FormListaSuporte(FlaskForm):
    pesquisa = StringField('Pesquisar')
    botao_submit = SubmitField('Buscar')


class FormCriarTopico(FlaskForm):
    nome_topico = StringField('Tópico', validators=[DataRequired(message='Favor inserir texto')])
    observacao = StringField('Observação')
    botao_submit = SubmitField('Cadastrar')


class FormEditarTopico(FlaskForm):
    nome_topico = StringField('Tópico', validators=[DataRequired(message='Favor inserir texto')])
    observacao = StringField('Observação')
    situacao = SelectField('Situação')
    botao_submit = SubmitField('Cadastrar')


class FormCriarPostagemCentral(FlaskForm):
    titulo = StringField('Título Publicação', validators=[DataRequired(message='Necessário inserir título')])
    body = CKEditorField('Publicação',
                         validators=[DataRequired(message='Necessário inserir recado')])
    cargo = SelectField('Cargo')
    id_topico = SelectField('Tópico')
    visivel = SelectField('Privacidade')
    botao_submit = SubmitField('Cadastrar')

class FormEditarPostagemCentral(FlaskForm):
    titulo = StringField('Título Publicação', validators=[DataRequired(message='Necessário inserir título')])
    body = CKEditorField('Publicação',
                         validators=[DataRequired(message='Necessário inserir recado')])
    cargo = SelectField('Cargo')
    id_topico = SelectField('Tópico')
    visivel = SelectField('Privacidade')
    situacao = SelectField('Situação')
    botao_submit = SubmitField('Cadastrar')


class FormAlterarSenha(FlaskForm):
    senha_atual = PasswordField('Senha atual', validators=[DataRequired(message='Necessário inserir senha')])
    senha = PasswordField('Nova senha:', validators=[DataRequired(message='Inserir nova senha'), Length(8, 150)])
    confirmacao_senha = PasswordField('Confirme sua senha:', validators=[DataRequired(), EqualTo('senha', message='As senhas precisam ser iguais')])
    botao_submit = SubmitField('Atualizar')


class FormPesquisaCentral(FlaskForm):
    pesquisa = StringField('Pesquisar')
    botao_submit = SubmitField('Pesquisar')


class FormPesquisaRecadosAdmin(FlaskForm):
    data_inicial = DateField('Data Inicial', format='%Y-%m-%d')
    data_final = DateField('Data Final', format='%Y-%m-%d')
    botao_submit = SubmitField('Pesquisar')


class FormAlterarOrdemFila(FlaskForm):
    ordem_fila = SelectField('Ordem Fila')
    botao_submit = SubmitField('Alterar')