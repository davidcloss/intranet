from flask import render_template, redirect, url_for, flash, request, session
from Intranet import app, database, bcrypt
from Intranet.forms import FormCriarConta, FormLogin, FormCadastroRamais, FormVinculoRamais
from Intranet.forms import FormEdicaoPerfil, FormRecadosFixo, FormCriarTopico, FormEditarTopico
from Intranet.forms import FormCriarPostagemCentral, FormTramitesSuporteResposta
from Intranet.forms import FormTiposSuporte, FormSuporte, FormListaSuporte, FormEditarPostagemCentral
from Intranet.forms import FormAlterarSenha, FormEncaminharSuporte, FormPesquisaCentral
from Intranet.forms import FormPesquisaRecadosAdmin, FormAlterarOrdemFila
from Intranet.models import Usuarios, Cargos, Setores, Situacoes, Ramais, UsuarioRamal
from Intranet.models import EdicaoPerfil, Posts, Tipos_recados, SituacoesSuporte, TopicosCentralSoucoes
from Intranet.models import TiposSuporte, TramitesSuporte, Suporte, GrauUrgencia
from Intranet.models import VisualizacaoCentralSolucoes, RegistroLogin
from flask_login import login_user, logout_user, current_user, login_required
from sqlalchemy import not_, desc, distinct, and_
from sqlalchemy.orm import aliased
import time as tempo
from datetime import datetime, timedelta, time


def converte_data_string(data):
    data_formatada = data.strftime('%d/%m/%Y')
    return data_formatada


app.add_template_global(converte_data_string, 'converte_data_string')


def retorna_dados_curent_user():
    usuario = Usuarios.query.filter_by(id=current_user.id).first()
    return usuario

app.add_template_global(retorna_dados_curent_user, 'current_user_data')


def retorna_setor_current_user():
    usuario = retorna_dados_curent_user()
    setor = Setores.query.filter_by(id=usuario.id_setor).first()
    return setor


app.add_template_global(retorna_setor_current_user, 'retorna_setor_current_user')


def retorna_cargo_current_user():
    usuario = retorna_dados_curent_user()
    cargo = Cargos.query.filter_by(id=usuario.id_cargo).first()
    return cargo


app.add_template_global(retorna_cargo_current_user, 'retorna_cargo_current_user')


def retorna_tipos_recados(id):
    tipos = Tipos_recados.query.filter_by(id=id).order_by(Tipos_recados.id).first()
    tipos = tipos.classe_html
    return tipos


app.add_template_global(retorna_tipos_recados, 'retorna_tipos_recados')


def retorna_hierarquia_current_user():
    usuario = Usuarios.query.filter_by(id=current_user.id).first()
    hierarquia_setor = Setores.query.filter_by(id=usuario.id_setor).first().hierarquia
    hierarquia_cargo = Cargos.query.filter_by(id=usuario.id_cargo).first().grau_hierarquia
    return hierarquia_cargo, hierarquia_setor


def retorna_classe_html_suporte(chamado):
    classe_html = SituacoesSuporte.query.filter_by(id=chamado.id_situacao_suporte).first().classe_html
    return classe_html


app.add_template_global(retorna_classe_html_suporte, 'retorna_classe_html_suporte')

def retorna_data_hora(data):
    data_modificada = data.strftime('%d/%m/%Y %H:%M')
    return data_modificada


app.add_template_global(retorna_data_hora, 'retorna_data_hora')


def define_data_ultimo_tramite(suporte):
    if suporte.data_ultimo_tramite:
        data = suporte.data_ultimo_tramite
    else:
        data = suporte.data_cadastro
    return data

app.add_template_global(define_data_ultimo_tramite, 'define_data_ultimo_tramite')


def retorna_posts(dias=15, data_inicial=None, data_final=None):
    if not data_inicial and not data_final:
        data_atual = datetime.now()
        data_inicio_consulta = data_atual - timedelta(days=dias)

        recados = database.session.query(Posts).filter(and_(Posts.identificador == 1,
        Posts.data_cadastro <= data_atual,
        Posts.data_cadastro >= data_inicio_consulta
        )).order_by(Posts.data_cadastro.desc()).all()
        return recados
    else:

        recados = Posts.query.filter(
    Posts.identificador.in_([1, 2]),
    Posts.data_cadastro >= data_inicial,
    Posts.data_cadastro <= data_final
).order_by(Posts.data_cadastro.desc()).all()
        return recados


app.add_template_global(retorna_posts, 'retorna_posts')


def retorna_cargos_select_field():
    cargo_current_user = retorna_cargo_current_user()
    cargos = Cargos.query.filter(and_(Cargos.id != 1,
                                 Cargos.grau_hierarquia < cargo_current_user.grau_hierarquia)).order_by(Cargos.grau_hierarquia).all()
    return cargos


def retorna_setores_select_field():
    setor_current_user = retorna_setor_current_user()
    setores = Setores.query.filter(and_(Setores.id != 9,
                                        Setores.hierarquia <= setor_current_user.hierarquia)
                                   ).order_by(Setores.nome_setor).all()
    return setores


@app.route('/criarconta', methods=['GET', 'POST'])
def criar_conta():
    if current_user.id != 1:
        return redirect(url_for('home'))
    else:
        form_criar_conta = FormCriarConta()
        form_criar_conta.id_cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in retorna_cargos_select_field()]
        form_criar_conta.id_setor.choices = [(setor.id, setor.nome_setor) for setor in retorna_setores_select_field()]
        if form_criar_conta.validate_on_submit():
            pesquisa_email = Usuarios.query.filter_by(email_pessoal=form_criar_conta.email_pessoal.data).first()
            pesquisa_username = Usuarios.query.filter_by(username=form_criar_conta.username.data).first()
            if pesquisa_email:
                flash('E-mail pessoal já cadastrado, favor verificar.')
            elif pesquisa_username:
                flash('Username pessoal já cadastrado, favor verificar.')
            else:
                senha_crip = bcrypt.generate_password_hash(form_criar_conta.senha.data).decode('UTF-8')
                usuario = Usuarios(nome_usuario=form_criar_conta.nome_usuario.data,
                                   username=form_criar_conta.username.data,
                                   email_uso=form_criar_conta.email_uso.data,
                                   email_pessoal=form_criar_conta.email_pessoal.data,
                                   senha=senha_crip,
                                   id_setor=form_criar_conta.id_setor.data,
                                   id_cargo=form_criar_conta.id_cargo.data)
                database.session.add(usuario)
                database.session.commit()
                flash(f'Conta criada para {form_criar_conta.username.data}!', 'alert-success')
                return redirect(url_for('home'))
        return render_template('criar_conta.html', form_criar_conta=form_criar_conta)



@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html', usuarios=Usuarios, setores=Setores, cargos=Cargos)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form_login = FormLogin()
    if form_login.validate_on_submit():
        usuario = Usuarios.query.filter_by(email_pessoal=form_login.email.data).first()
        if not usuario:
            flash('Usuário não cadastrado', 'alert-danger')
        elif usuario.situacao_usuario != 1:
            flash('Entre em contato com sua supervisão ou TI', 'alert-danger')
        elif usuario and bcrypt.check_password_hash(usuario.senha, form_login.senha.data):
            login_user(usuario, remember=form_login.lembrar_dados.data)
            session['hierarquia'] = retorna_hierarquia_current_user()
            session['hierarquia_cargo'], session['hierarquia_setor'] = session.get('hierarquia')
            login = RegistroLogin(usuario_id=current_user.id,
                                  data_login=datetime.now())
            database.session.add(login)
            database.session.commit()
            flash(f"Login bem sucedido em: {form_login.email.data}!", 'alert-success')
            par_next = request.args.get('next')
            if par_next:
                return redirect(par_next)
            else:
                return redirect(url_for('home'))
        else:
            flash('E-mail ou senha incorretos!', 'alert-danger')  # Alterado para mensagem mais genérica
    return render_template('login.html', form_login=form_login)


@app.before_request
def registrar_logout():
    if 'logged_in' in session and request.endpoint != 'sair':
        # Aqui você pode adicionar lógica para registrar o logout
        usuario_id = session.get('usuario_id')
        if usuario_id:
            registro_login = RegistroLogin.query.filter_by(usuario_id=usuario_id, data_logout=None).first()
            if registro_login:
                registro_login.data_logout = datetime.now()
                database.session.commit()


@app.route('/sair')
@login_required
def sair():
    if current_user.is_authenticated:
        usuario_id = current_user.id
        logout_user()
        registro_login = RegistroLogin.query.filter_by(usuario_id=usuario_id, data_logout=None).first()
        if registro_login:
            registro_login.data_logout = datetime.now()
            database.session.commit()
        session.pop('logged_in', None)
        session.clear()
        flash(f"Logout realizado com sucesso!", 'alert-success')
    return redirect(url_for('login'))


@app.route('/ramais/cadastros', methods=['GET', 'POST'])
@login_required
def cadastro_ramais():
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        form = FormCadastroRamais()
        if form.validate_on_submit():
            ramal = Ramais.query.filter_by(ramal=form.ramal.data).first()
            if ramal:
                flash(f"Ramal já existe!", 'alert-danger')
            else:
                ramal = Ramais(ramal=form.ramal.data)
                database.session.add(ramal)
                database.session.commit()
                flash(f"Ramal cadastrado com sucesso!", 'alert-success')
                return render_template('home.html')
        return render_template('cadastro_ramal.html', form=form)
    else:
        return redirect(url_for('home'))



@app.route('/contatos/lista/inativos')
@login_required
def lista_contatos_inativos():
    usuarios = Usuarios.query.filter_by(situacao_usuario=2).all()
    return render_template('listacontatos.html', usuarios=usuarios, setor=Setores,
                           cargos=Cargos, usuario_ramal=UsuarioRamal, ramais=Ramais)


def busca_todos_usuarios():
    usuarios = (
        Usuarios.query
        .join(Setores, Usuarios.id_setor == Setores.id)
        .filter(Usuarios.situacao_usuario == 1,
                Usuarios.id != 1)
        .order_by(Setores.nome_setor).order_by(Usuarios.nome_usuario)
        .all()
    )
    return usuarios


@app.route('/contatos/lista')
def lista_contatos():
    usuarios = busca_todos_usuarios()
    return render_template('listacontatos.html', usuarios=usuarios, setor=Setores,
                           cargos=Cargos, usuario_ramal=UsuarioRamal, ramais=Ramais)


@app.route('/ramais/lista')
@login_required
def lista_ramais():
    situacoes = Situacoes()
    ramais = Ramais.query.order_by(Ramais.ramal).all()
    return render_template('listaramais.html', ramais=ramais, situacoes=situacoes)


@app.route('/ramais/edicao/<ramal_id>', methods=['GET', 'POST'])
@login_required
def edicao_ramais(ramal_id):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        ramais = Ramais.query.filter_by(id=ramal_id).first()
        form = FormCadastroRamais(obj=ramais)
        form.situacoes_ramais.choices = [(situacao.id, situacao.nome_situacao) for situacao in
                                         Situacoes.query.all()]
        if form.validate_on_submit():
            if Ramais.query.filter(Ramais.ramal == form.ramal.data, Ramais.id != ramal_id).first():
                flash(f"Ramal já cadastrado!", 'alert-danger')
            else:
                form.populate_obj(ramais)
                database.session.commit()
                flash(f"Ramal atualizado com sucesso!", 'alert-success')
                return redirect(url_for('lista_ramais'))
        return render_template('edicao_ramais.html', form=form)
    else:
        return redirect(url_for('home'))

@app.route('/ramais/vinculoramais', methods=['GET', 'POST'])
@login_required
def vinculo_ramais():
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        form = FormVinculoRamais()
        form.id_usuario.choices = [(usuario.id, usuario.nome_usuario) for usuario in
                                   Usuarios.query.order_by(Usuarios.nome_usuario).all()]
        form.id_ramal.choices = [(ramal.id, ramal.ramal) for ramal in
                                 Ramais.query.filter_by(situacoes_ramais=1).order_by(Ramais.ramal).all()]
        if form.validate_on_submit():
            vinculo = UsuarioRamal(id_usuario=form.id_usuario.data,
                                   id_ramal=form.id_ramal.data,
                                   id_usuario_cadastro=current_user.id)
            try:
                database.session.add(vinculo)
                database.session.commit()
                flash(f"Cadastro atualizado com sucesso!", 'alert-success')
                return redirect(url_for('lista_contatos'))
            except:
                flash(f"Usuário já cadastrado!", 'alert-danger')
        return render_template('vinculo_ramais.html', form=form)
    else:
        return redirect(url_for('home'))


@app.route('/contatos/perfil/<id_usuario>/editar', methods=['GET', 'POST'])
@login_required
def editar_perfil(id_usuario):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5 or session.get('hierarquia_setor') is not None or session.get('hierarquia_cargo') is not None:
        usuario = Usuarios.query.get_or_404(int(id_usuario))
        usuario_ramal = UsuarioRamal.query.filter_by(id_usuario=int(usuario.id)).first()
        if usuario_ramal:
            perfil = EdicaoPerfil(
                nome_usuario=usuario.nome_usuario,
                username=usuario.username,
                email_uso=usuario.email_uso,
                email_pessoal=usuario.email_pessoal,
                id_cargo=usuario.id_cargo,
                id_setor=usuario.id_setor,
                situacao_usuario = usuario.situacao_usuario,
                id_ramal=usuario_ramal.id_ramal,
                id_usuario_cadastro=current_user.id
            )
        else:
            perfil = EdicaoPerfil(
                nome_usuario=usuario.nome_usuario,
                username=usuario.username,
                email_uso=usuario.email_uso,
                email_pessoal=usuario.email_pessoal,
                id_cargo=usuario.id_cargo,
                situacao_usuario=usuario.situacao_usuario,
                id_setor=usuario.id_setor,
                id_usuario_cadastro=current_user.id
            )

        form = FormEdicaoPerfil(obj=perfil)
        if current_user.id == 1 and int(id_usuario) == 1:
            form.id_cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in
                                  Cargos.query.order_by(Cargos.grau_hierarquia).all()]
            form.id_setor.choices = [(setor.id, setor.nome_setor) for setor in
                                  Setores.query.order_by(Setores.nome_setor).all()]
        else:
            form.id_cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in
                                     retorna_cargos_select_field()]
            form.id_setor.choices = [(setor.id, setor.nome_setor) for setor in
                                     retorna_setores_select_field()]
        form.id_ramal.choices = [(ramal.id, ramal.ramal) for ramal in
                                 Ramais.query.order_by(Ramais.ramal).all()]
        form.situacao_usuario.choices = [(situacao.id, situacao.nome_situacao) for situacao in
                                 Situacoes.query.order_by(Situacoes.id).all()]

        if form.validate_on_submit():
            if usuario_ramal:
                novo_email = Usuarios.query.filter(not_(Usuarios.id == id_usuario),
                                                   Usuarios.email_pessoal == form.email_pessoal.data).first()
                if novo_email:
                    flash('E-mail já utilizado em outra conta', 'alert-warning')
                else:
                    usuario.nome_usuario = form.nome_usuario.data
                    usuario.username = form.username.data
                    usuario.email_uso = form.email_uso.data
                    usuario.email_pessoal = form.email_pessoal.data
                    usuario.id_setor = form.id_setor.data
                    usuario.id_cargo = form.id_cargo.data
                    usuario.situacao_usuario = form.situacao_usuario.data
                    form.populate_obj(usuario_ramal)
                    database.session.commit()
                    return redirect(url_for('lista_contatos'))

            else:
                novo_email = Usuarios.query.filter(not_(Usuarios.id == id_usuario),
                                                   Usuarios.email_pessoal == form.email_pessoal.data).first()
                if novo_email:
                    flash('E-mail já utilizado em outra conta', 'alert-warning')
                else:
                    form.populate_obj(usuario)
                    usuario.nome_usuario = form.nome_usuario.data
                    usuario.username = form.username.data
                    usuario.email_pessoal = form.email_pessoal.data
                    usuario.email_uso = form.email_uso.data
                    usuario.id_setor = form.id_setor.data
                    usuario.id_cargo = form.id_cargo.data
                    usuario.situacao_usuario = form.situacao_usuario.data
                    vinculo = UsuarioRamal(id_usuario=usuario.id,
                                           id_ramal=form.id_ramal.data,
                                           id_usuario_cadastro=current_user.id)
                    database.session.add(vinculo)

                    database.session.commit()
                    flash(f"Perfil atualizado com sucesso!", 'alert-success')
                    return redirect(url_for('lista_contatos'))

        return render_template('edicao_perfil.html', form=form)
    else:
        return redirect(url_for('home'))

@app.route('/centraldesolucoes')
@login_required
def central_de_solucoes():
    return render_template('central_de_solucoes.html')


def retorna_id_setor(setor):
    if setor == 'atendimento':
        id_setor = 6
        return id_setor
    elif setor == 'contabilidade':
        id_setor = 2
        return id_setor
    elif setor == 'desenvolvimento':
        id_setor = 7
        return id_setor
    elif setor == 'direcao':
        id_setor = 8
        return id_setor
    elif setor == 'departamentopessoal':
        id_setor = 1
        return id_setor
    elif setor == 'financeiro':
        id_setor = 5
        return id_setor
    elif setor == 'fiscal':
        id_setor = 3
        return id_setor
    elif setor == 'societario':
        id_setor = 4
        return id_setor


@app.route('/centraldesolucoes/<setor>')
@login_required
def central_atendimento(setor):
    id_setor = retorna_id_setor(setor)
    setor_c = Setores.query.filter_by(id=id_setor).first()
    posts = Posts.query.filter_by(identificador=3, setor=id_setor).order_by(Posts.views.desc()).limit(10).all()
    return render_template('central_atendimento.html', setor_c=setor_c, setor_o=setor, posts=posts)


@app.route('/centraldesolucoes/<setor>/topicos/criar', methods=['GET', 'POST'])
@login_required
def criar_topicos(setor):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        id_setor = retorna_id_setor(setor)
        setor_c = Setores.query.filter_by(id=id_setor).first()
        form = FormCriarTopico()
        if form.validate_on_submit():
            central = TopicosCentralSoucoes(nome_topico=form.nome_topico.data,
                                            observacao=form.observacao.data,
                                            setor=retorna_id_setor(setor),
                                            id_usuario_cadastro=current_user.id)
            database.session.add(central)
            database.session.commit()
            flash('Cadastrado com sucesso', 'alert-success')
            return redirect(url_for('lista_topicos', setor=setor))
        return render_template('cadastro_topico.html', form=form, setor_c=setor_c, setor_o=setor)
    else:
        return redirect(url_for('home'))


@app.route('/centraldesolucoes/<setor>/topicos/lista')
@login_required
def lista_topicos(setor):
    id_setor = retorna_id_setor(setor)
    setor_c = Setores.query.filter_by(id=id_setor).first()
    topicos = TopicosCentralSoucoes.query.filter_by(setor=id_setor).order_by(TopicosCentralSoucoes.nome_topico).all()
    return render_template('lista_topicos.html', setor_c=setor_c, topicos=topicos, setores=Setores, situacoes=Situacoes, setor_o=setor)


@app.route('/centraldesolucoes/<setor>/topicos/<id_topico>/lista', methods=['GET', 'POST'])
@login_required
def editar_topicos(setor, id_topico):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        topico = TopicosCentralSoucoes.query.filter_by(id=id_topico).first()
        form = FormEditarTopico(obj=topico)
        form.situacao.choices = [(situacao.id, situacao.nome_situacao) for situacao in
                                         Situacoes.query.all()]
        id_setor = retorna_id_setor(setor)
        setor_c = Setores.query.filter_by(id=id_setor).first()
        if form.validate_on_submit():
            form.populate_obj(topico)
            topico.id_usuario_cadastro = current_user.id
            database.session.commit()
            flash('Atualizado com sucesso', 'alert-success')
            return redirect(url_for('lista_topicos', setor=setor))
        return render_template('editar_topico.html', setor_c=setor_c, form=form, setores=Setores, situacoes=Situacoes, setor_o=setor)
    else:
        return redirect(url_for('home'))


@app.route('/centraldesolucoes/<setor>/publicacoes/criar', methods=['GET', 'POST'])
@login_required
def criar_publicacoes_central(setor):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        id_setor = retorna_id_setor(setor)
        setor_c = Setores.query.filter_by(id=id_setor).first()
        form = FormCriarPostagemCentral()
        privacidade = [(1, 'Público'), (2, 'Privado para cargos iguais ou acima'),
                       (3, 'Visivel somente para cargos administradores')]
        form.visivel.choices = [(priv[0], priv[1]) for priv in privacidade]
        form.cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in Cargos.query.order_by(Cargos.nome_cargo).all()]
        form.id_topico.choices = [(topico.id, topico.nome_topico) for topico in TopicosCentralSoucoes.query.filter(TopicosCentralSoucoes.situacao==1, TopicosCentralSoucoes.setor==id_setor).order_by(TopicosCentralSoucoes.nome_topico).all()]
        if form.validate_on_submit():
            if form.visivel == '2' and form.cargo == '1':
                flash('Para esse tipo de privacidade selecionada, é necessário escolher um cargo', 'alert-warning')
            else:
                publicacao = Posts(identificador=3,
                                    titulo=form.titulo.data,
                                    body=form.body.data,
                                    visivel=int(form.visivel.data),
                                    cargo=form.cargo.data,
                                    setor=id_setor,
                                    id_topico=form.id_topico.data,
                                    id_usuario_autor=current_user.id)
                database.session.add(publicacao)
                database.session.commit()
                flash('Cadastrado com sucesso.', 'alert-success')
                return redirect(url_for('central_atendimento', setor=setor))
        return render_template('criar_publicacoes_central.html', setor_c=setor_c, form=form, setor_o=setor)
    else:
        return redirect(url_for('home'))


@app.route('/centraldesolucoes/<setor>/publicacoes/lista', methods=['GET', 'POST'])
@login_required
def lista_publicacoes(setor):
    id_setor = retorna_id_setor(setor)
    setor_c = Setores.query.filter_by(id=id_setor).first()
    pesquisa = session.get('pesquisa_central')
    form = FormPesquisaCentral()
    if pesquisa:
        form.pesquisa.data = pesquisa

    if pesquisa:
        results = Posts.query.filter(
            (Posts.identificador == 3) &
            ((Posts.titulo.ilike(f'%{pesquisa}%')) |
             (Posts.body.ilike(f'%{pesquisa}%')))
        ).order_by(Posts.views.desc()).all()
        session.pop('pesquisa_central', None)

    else:
        results = Posts.query.filter_by(identificador=3, setor=id_setor).limit(50).all()

    if form.validate_on_submit():
        session['pesquisa_central'] = form.pesquisa.data
        return redirect(url_for('lista_publicacoes', setor=setor, pesquisa=form.pesquisa.data))

    return render_template('lista_publicacoes.html', form=form, setor_c=setor_c, setor_o=setor, publicacoes=results,
                           topicos=TopicosCentralSoucoes, usuarios=Usuarios, cargos=Cargos)


@app.route('/centraldesolucoes/<setor>/publicacoes/<id_publicacao>', methods=['GET', 'POST'])
@login_required
def publicacoes(setor, id_publicacao):
    id_setor = retorna_id_setor(setor)
    setor_c = Setores.query.filter_by(id=id_setor).first()
    publicacao = Posts.query.filter_by(id=id_publicacao).first()
    view = VisualizacaoCentralSolucoes(id_postagens=id_publicacao,
                                       id_usuario=current_user.id,
                                       data_viz=datetime.now())
    database.session.add(view)
    database.session.commit()
    return render_template('publicacoes_central.html', setor_c=setor_c, setor_o=setor, publicacao=publicacao, usuarios=Usuarios, topicos=TopicosCentralSoucoes, cargos=Cargos)


@app.route('/centraldesolucoes/<setor>/publicacoes/<id_publicacao>/editar', methods=['GET', 'POST'])
@login_required
def editar_publicacoes(setor, id_publicacao):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        id_setor = retorna_id_setor(setor)
        setor_c = Setores.query.filter_by(id=id_setor).first()
        publi = Posts.query.filter_by(id=id_publicacao).first()
        form = FormEditarPostagemCentral(obj=publi)
        privacidade = [(1, 'Público'), (2, 'Privado para cargos iguais ou acima'), (3, 'Visivel somente para cargos administradores')]
        form.visivel.choices = [(priv[0], priv[1]) for priv in privacidade]
        form.cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in Cargos.query.order_by(Cargos.grau_hierarquia).all()]
        form.id_topico.choices = [(topico.id, topico.nome_topico) for topico in
                                  TopicosCentralSoucoes.query.filter_by(situacao=1).order_by(
                                      TopicosCentralSoucoes.nome_topico).all()]
        form.situacao.choices = [(situacao.id, situacao.nome_situacao) for situacao in Situacoes.query.all()]

        if form.validate_on_submit():
            if form.visivel.data == '2' and form.cargo.data == '1':
                flash('Para esse tipo de privacidade selecionada, é necessário escolher um cargo', 'alert-warning')
            else:
                if form.situacao.data == '2':
                    publi.identificador = None
                form.populate_obj(publi)
                publi.visivel = int(form.visivel.data)
                publi.data_cadastro = datetime.now()
                publi.id_usuario_autor = current_user.id
                database.session.commit()
                flash('Atualizado com sucesso', 'alert-success')
                return redirect(url_for('publicacoes', setor=setor, id_publicacao=id_publicacao))
        return render_template('editar_publicacoes_central.html', setor_c=setor_c, form=form, tipo=type(publi.visivel), setor_o=setor)
    else:
        return redirect(url_for('home'))


@app.route('/mural/recadofixo/criar', methods=['GET', 'POST'])
@login_required
def criar_recado_fixo():
    form = FormRecadosFixo()
    form.id_usuario_destino.choices = [(usuario.id, usuario.nome_usuario) for usuario in
                                       Usuarios.query.order_by(Usuarios.nome_usuario).all()]
    form.setor.choices = [(setor.id, setor.nome_setor) for setor in
                          Setores.query.order_by(Setores.nome_setor).all()]
    form.cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in
                           Cargos.query.order_by(Cargos.nome_cargo).all()]
    if form.validate_on_submit():
        if len(form.titulo.data) > 100:
            flash('O título pode ter no máximo 100 caracteres!', 'alert-warning')
        else:
            if form.id_usuario_destino.data == '1' and form.setor.data == '9' and form.cargo.data == '1':
                posts = Posts(identificador=1,
                                  titulo=form.titulo.data,
                                  body=form.body.data,
                                  id_usuario_autor=current_user.id,
                                  id_tipo_recado=1)
                database.session.add(posts)
                database.session.commit()
            elif form.id_usuario_destino.data != '1':
                usuario_destino = Usuarios.query.filter_by(id=form.id_usuario_destino.data).first()
                posts = Posts(identificador=1,
                                  titulo=form.titulo.data,
                                  body=form.body.data,
                                  setor=int(usuario_destino.id_setor),
                                  cargo=int(usuario_destino.id_cargo),
                                  id_usuario_destino=usuario_destino.id,
                                  id_usuario_autor=current_user.id,
                                  id_tipo_recado=2)
                database.session.add(posts)
                database.session.commit()
            elif form.cargo.data != '1' and form.setor.data != '9':
                posts = Posts(identificador=1,
                                  titulo=form.titulo.data,
                                  body=form.body.data,
                                  setor=int(form.setor.data),
                                  cargo=int(form.cargo.data),
                                  id_usuario_autor=int(current_user.id),
                                  id_tipo_recado=3)
                database.session.add(posts)
                database.session.commit()
            elif form.cargo.data != '1':
                posts = Posts(identificador=1,
                                  titulo=form.titulo.data,
                                  body=form.body.data,
                                  cargo=int(form.cargo.data),
                                  id_usuario_autor=int(current_user.id),
                                  id_tipo_recado=4)
                database.session.add(posts)
                database.session.commit()
            elif form.setor.data != '9':
                posts = Posts(identificador=1,
                                  titulo=form.titulo.data,
                                  body=form.body.data,
                                  setor=int(form.setor.data),
                                  id_usuario_autor=int(current_user.id),
                                  id_tipo_recado=5)
                database.session.add(posts)
                database.session.commit()
            else:
                flash('Situação não reconhecida, favor contate o setor de desenvolvimento',
                          'alert-danger')
            flash(f"Post cadastrado!", 'alert-success')
            return redirect(url_for('home'))

    return render_template('criar_recado_fixo.html', form=form)


@app.route('/mural/recadofixo/<id_recado>/editar', methods=['GET', 'POST'])
@login_required
def editar_recados_fixos(id_recado):
    posts = Posts.query.filter_by(id=id_recado).first()
    form = FormRecadosFixo(obj=posts)
    form.id_usuario_destino.choices = [(usuario.id, usuario.nome_usuario) for usuario in
                                       Usuarios.query.order_by(Usuarios.nome_usuario).all()]
    form.setor.choices = [(setor.id, setor.nome_setor) for setor in
                          Setores.query.order_by(Setores.nome_setor).all()]
    form.cargo.choices = [(cargo.id, cargo.nome_cargo) for cargo in
                           Cargos.query.order_by(Cargos.nome_cargo).all()]
    if form.validate_on_submit():
        if len(form.titulo.data) > 100:
            flash('O título pode ter no máximo 100 caracteres!', 'alert-warning')
        else:
                # Caso edite aqui, editar também edições recados
            if form.id_usuario_destino.data == '1' and form.setor.data == '9' and form.cargo.data == '1':
                posts.identificador = 1
                posts.titulo = form.titulo.data
                posts.body = form.body.data
                posts.id_usuario_autor = current_user.id
                posts.id_tipo_recado = 1
                posts.id_usuario_destino = None
                posts.cargo = None
                posts.setor = None
            elif form.id_usuario_destino.data != '1':
                usuario_destino = Usuarios.query.filter_by(id=form.id_usuario_destino.data).first()
                posts.identificador = 1
                posts.titulo = form.titulo.data
                posts.body = form.body.data
                posts.setor = usuario_destino.id_setor
                posts.cargo = usuario_destino.id_cargo
                posts.id_usuario_destino = usuario_destino.id
                posts.id_usuario_autor = current_user.id
                posts.id_tipo_recado = 2
            elif form.cargo.data != '1' and form.setor.data != '9':
                posts.identificador = 1
                posts.titulo = form.titulo.data
                posts.body = form.body.data
                posts.setor = int(form.setor.data)
                posts.cargo = int(form.cargo.data)
                posts.id_usuario_destino = None
                posts.id_usuario_autor = current_user.id
                posts.id_tipo_recado = 3
            elif form.cargo.data != '1':
                posts.identificador = 1
                posts.titulo = form.titulo.data
                posts.body = form.body.data
                posts.cargo = int(form.cargo.data)
                posts.setor = None
                posts.id_usuario_autor = current_user.id
                posts.id_tipo_recado = 4
                posts.id_usuario_destino = None
            elif form.setor.data != '9':
                posts.identificador = 1
                posts.titulo = form.titulo.data
                posts.body = form.body.data
                posts.setor = int(form.setor.data)
                posts.id_usuario_autor = current_user.id
                posts.id_tipo_recado = 5
                posts.cargo = None
                posts.id_usuario_destino = None
            else:
                flash('Situação não reconhecida, favor contate o setor de desenvolvimento',
                          'alert-danger')
            posts.data_cadastro = datetime.now()
            database.session.commit()
            flash(f"Post cadastrado!", 'alert-success')
            return redirect(url_for('home'))
    return render_template('criar_recado_fixo.html', form=form)


@app.route('/suportes')
@login_required
def central_suporte():
    return render_template('suportes.html')


@app.route('/suportes/tiposuporte/cadastro', methods=['GET', 'POST'])
@login_required
def cadastro_tipos_suporte():
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        form = FormTiposSuporte()
        if form.validate_on_submit():
            verifica_tipo = TiposSuporte.query.filter_by(nome_tipo_suporte=form.nome_tipo_suporte.data).first()
            if verifica_tipo:
                flash('Tipo Suporte já cadastrado.', 'alert-warning')
            else:
                tipo_suporte = TiposSuporte(nome_tipo_suporte=form.nome_tipo_suporte.data,
                                            id_usuario_cadastro=current_user.id)
                database.session.add(tipo_suporte)
                database.session.commit()
                flash('Tipo suporte cadastrado com sucesso', 'alert-success')
                return redirect(url_for('lista_tipos_suporte'))
        return render_template('criar_tipos_suporte.html', form=form)
    else:
        return redirect(url_for('home'))


@app.route('/suportes/tiposuporte/lista')
@login_required
def lista_tipos_suporte():
    tipos = TiposSuporte.query.order_by(TiposSuporte.nome_tipo_suporte).all()
    situacao = Situacoes()
    return render_template('lista_tipos_suporte.html', tipos=tipos, situacao=situacao)


@app.route('/suportes/tiposuporte/<id_suporte>/editar', methods=['GET', 'POST'])
def editar_tipos_suporte(id_suporte):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5:
        tipo = TiposSuporte.query.filter_by(id=id_suporte).first()
        form = FormTiposSuporte(obj=tipo)
        if form.validate_on_submit():
            verifica_tipo = TiposSuporte.query.filter(TiposSuporte.id != tipo.id,
                            TiposSuporte.nome_tipo_suporte == form.nome_tipo_suporte.data).all()
            if verifica_tipo:
                flash('Tipo Suporte já cadastrado.', 'alert-warning')
            else:
                form.populate_obj(tipo)
                tipo.id_usuario_cadastro = current_user.id
                database.session.commit()
                flash('Tipo suporte atualizado com sucesso', 'alert-success')
                return redirect(url_for('lista_tipos_suporte'))
        return render_template('criar_tipos_suporte.html', form=form)
    else:
        return redirect(url_for('home'))


def id_secundario_tabela_tramites_suporte(tramite_cadastrado):
    tramite = TramitesSuporte.query.filter_by(id_suporte=tramite_cadastrado.id_suporte).filter(TramitesSuporte.id_secundario.isnot(None)).order_by(TramitesSuporte.id.desc()).first()
    if tramite:
        print('yay')
        return tramite.id_secundario + 1
    else:
        print('nah')
        return 1


def cria_texto_recado_suporte(id_body=None, titulo_suporte=None, chamado_id=None, id_usuario=None):
    if id_body == 1:
        nome_usuario = Usuarios.query.filter_by(id=id_usuario).first().nome_usuario
        body = f"""<span>{nome_usuario} encaminhou um suporte para você.</span> <span>Título suporte: {titulo_suporte}, ID: {chamado_id}</span>"""
        return body
    elif id_body == 2:
        nome_usuario = Usuarios.query.filter_by(id=id_usuario).first().nome_usuario
        body = f"""<span>{nome_usuario} encaminhou a autoria de um suporte para você.</span> 

        <span>Título suporte: {titulo_suporte}, ID: {chamado_id}</span>"""
        return body
    elif id_body == 3:
        body = f"""
        Suporte: {chamado_id} - {titulo_suporte} finalizado sem sucesso.
        """
        return body
    elif id_body == 4:
        body = f"""
        Suporte: {chamado_id} - {titulo_suporte} está em execução.
        """
        return body
    elif id_body == 5:
        body = f"""
        Suporte: {chamado_id} - {titulo_suporte} está em fila de produção.
        """
        return body
    elif id_body == 6:
        body = f"""
        Suporte: {chamado_id} - {titulo_suporte} está aguardando retorno.
        """
        return body
    elif id_body == 7:
        body = f"""
        Suporte: {chamado_id} - {titulo_suporte} foi cadastrado.
        """
        return body


def cria_titulo_recado_suporte(id_titulo):
    if id_titulo == 1:
        titulo = 'Suporte encaminhado para você!'
        return titulo
    elif id_titulo == 2:
        titulo = 'Suporte finalizado sem sucesso!'
        return titulo
    elif id_titulo == 3:
        titulo = 'Suporte finalizado com sucesso!'
        return titulo
    elif id_titulo == 4:
        titulo = 'Suporte em execução!'
        return titulo
    elif id_titulo == 5:
        titulo = 'Suporte entrou na fila de produção!'
        return titulo
    elif id_titulo == 6:
        titulo = 'Suporte está aguardando retorno!'
        return titulo
    elif id_titulo == 7:
        titulo = 'Suporte cadastrado!'
        return titulo


def busca_suportes_fila(id_usuario):
    chamados_ordenados = Suporte.query.filter(
        Suporte.id_usuario_destino == id_usuario,
        Suporte.id_situacao_suporte != 8,
        Suporte.id_situacao_suporte != 9
    ).order_by(Suporte.ordem_fila.asc()).all()
    return chamados_ordenados


def busca_suportes_ordenados(id_usuario, valor_minimo_ordem_fila, id_suporte_alterado):
    suportes = Suporte.query.filter(
    Suporte.id_usuario_destino == id_usuario,
    Suporte.id_situacao_suporte != 8,
    Suporte.id_situacao_suporte != 9,
    Suporte.ordem_fila.isnot(None),  # Garante que ordem_fila não é nulo
    Suporte.ordem_fila >= int(valor_minimo_ordem_fila),
    Suporte.id != id_suporte_alterado
).order_by(Suporte.ordem_fila.asc()).all()
    return suportes


def busca_fila_suporte(id_usuario):
    suporte = Suporte.query.filter(
    (Suporte.id_situacao_suporte != 8) & (Suporte.id_situacao_suporte != 9),
    Suporte.id_usuario_destino == id_usuario,
    Suporte.ordem_fila != None
).order_by(Suporte.ordem_fila.desc()).first()
    try:
        if suporte.ordem_fila:
            return suporte.ordem_fila
    except:
        return 1



@app.route('/suporte/chamados/<id_usuario>/filaproducao')
@login_required
def fila_producao_suporte(id_usuario):
    lista = busca_suportes_fila(id_usuario)
    usuario_fila = Usuarios.query.filter_by(id=id_usuario).first().nome_usuario
    return render_template('fila_suporte.html', usuario_fila=usuario_fila, suportes=lista, usuarios=Usuarios, setores=Setores)


@app.route('/suporte/chamados/<id_chamado>/alterarordemfila', methods=['GET', 'POST'])
@login_required
def altera_ordem_fila_suporte(id_chamado):
    chamado = Suporte.query.filter_by(id=id_chamado).first()
    qtd_fila = busca_fila_suporte(chamado.id_usuario_destino) - 1
    fila = list(range(1, qtd_fila))
    form = FormAlterarOrdemFila()
    form.ordem_fila.choices = [(f, f'{f}') for f in fila]
    if form.validate_on_submit():
        try:
            print(form.errors)
            print('yay')
            valor_fila = int(form.ordem_fila.data)
            chamado.ordem_fila = valor_fila
            suportes_ajustar = busca_suportes_ordenados(chamado.id_usuario_destino, valor_fila, chamado.id)

            if suportes_ajustar:
                for su in suportes_ajustar:
                    valor_fila += 1
                    su.ordem_fila = valor_fila
            database.session.commit()
            flash('Ordem alterada com Sucesso', 'alert-success')
            return redirect(url_for('fila_producao_suporte', id_usuario=chamado.id_usuario_destino))
        except Exception as e:
            print('aaaa')
    return render_template('altera_ordem_chamados.html', situacoes_suporte=SituacoesSuporte, suporte=chamado,
                           usuarios=Usuarios, tipos_suportes=TiposSuporte, setores=Setores, grau_urgencia=GrauUrgencia, form=form)


@app.route('/suporte/chamados/<id_suporte>/adicionafila', methods=['GET', 'POST'])
@login_required
def adiciona_fila_suporte(id_suporte):
    suporte = Suporte.query.filter_by(id=id_suporte).first()
    valor_fila = busca_fila_suporte(suporte.id_usuario_destino) + 1
    suporte.ordem_fila = valor_fila
    suportes_ajustar = busca_suportes_ordenados(suporte.id_usuario_destino, suporte.ordem_fila, valor_fila)
    if suportes_ajustar:
        for su in suportes_ajustar:
            su.ordem_fila = valor_fila
            valor_fila += 1
    database.session.commit()
    return redirect(url_for('fila_producao_suporte', id_usuario=suporte.id_usuario_destino))


@app.route('/suporte/chamados/criar', methods=['GET', 'POST'])
@login_required
def criar_suporte():
    form_suporte = FormSuporte()

    form_suporte.id_tipo_suporte.choices = [(tipo.id, tipo.nome_tipo_suporte)
                                            for tipo in TiposSuporte.query.filter_by(situacao=1).order_by(TiposSuporte.nome_tipo_suporte).all()]

    form_suporte.id_setor_suporte.choices = [(setor.id, setor.nome_setor)
                                             for setor in
                                             Setores.query.order_by(Setores.nome_setor).all()]

    form_suporte.id_setor_destino_suporte.choices = [(setor.id, setor.nome_setor)
                        for setor in Setores.query.order_by(Setores.nome_setor).all()]

    form_suporte.id_usuario_destino.choices = [(usuario.id, usuario.nome_usuario) for usuario in Usuarios.query.filter_by(situacao_usuario=1).order_by(Usuarios.nome_usuario).all()]

    form_suporte.id_grau_urgencia.choices = [(grau.id, grau.nome_urgencia) for grau in GrauUrgencia.query.order_by(GrauUrgencia.id).all()]


    if form_suporte.validate_on_submit():
        titulo = Suporte.query.filter_by(titulo_suporte=form_suporte.titulo_suporte.data).first()
        if titulo:
            flash('Título ja utilizado em outro ticket', 'alert-warning')
        else:
            if form_suporte.ocultar.data:
                ocultar = 0
            else:
                ocultar = 1
            if int(form_suporte.id_setor_destino_suporte.data) == 9 and int(form_suporte.id_usuario_destino.data) == 1:
                flash('É necessário atribuir pelo menos um setor destino ou usuário destino', 'alert-warning')

            elif int(form_suporte.id_usuario_destino.data) != 1:
                usuario = Usuarios.query.filter_by(id=int(form_suporte.id_usuario_destino.data)).first()
                suporte = Suporte(id_tipo_suporte=int(form_suporte.id_tipo_suporte.data),
                                  titulo_suporte=form_suporte.titulo_suporte.data,
                                  id_setor_suporte=int(form_suporte.id_setor_suporte.data),
                                  id_usuario_autor=current_user.id,
                                  id_usuario_destino=int(form_suporte.id_usuario_destino.data),
                                  id_setor_destino_suporte=usuario.id_setor,
                                  id_grau_urgencia=int(form_suporte.id_grau_urgencia.data),
                                  visivel=ocultar)
                database.session.add(suporte)
                database.session.commit()
                suporte_cadastrado = Suporte.query.filter_by(titulo_suporte=form_suporte.titulo_suporte.data).first()

                autor = Usuarios.query.filter_by(id=suporte_cadastrado.id_usuario_autor).first()
                destino = Usuarios.query.filter_by(id=suporte_cadastrado.id_usuario_destino).first()

                tramite = TramitesSuporte(id_suporte=suporte_cadastrado.id,
                                          body_tramite=form_suporte.body_tramite.data,
                                          id_autor=current_user.id,
                                          ocultar=ocultar,
                                          id_situacao_tramite=1)

                titulo = cria_titulo_recado_suporte(7)
                body_recado = cria_texto_recado_suporte(id_body=7, titulo_suporte=suporte_cadastrado.titulo_suporte,
                                                        chamado_id=suporte_cadastrado.id)

                post_destino = Posts(identificador=1,
                                     id_usuario_destino=destino.id,
                                     cargo=destino.id_cargo,
                                     setor=destino.id_setor,
                                     id_tipo_recado=2,
                                     id_usuario_autor=1,
                                     titulo=titulo,
                                     body=body_recado)

                post_autor = Posts(identificador=1,
                                   id_usuario_destino=autor.id,
                                   cargo=autor.id_cargo,
                                   setor=autor.id_setor,
                                   id_tipo_recado=2,
                                   id_usuario_autor=1,
                                   titulo=titulo,
                                   body=body_recado)

                database.session.add(post_destino)
                database.session.add(post_autor)
                database.session.add(tramite)
                database.session.commit()
                tempo.sleep(0.2)
                tramite_cadastrado = TramitesSuporte.query.filter_by(body_tramite=tramite.body_tramite).first()
                id_secundario = id_secundario_tabela_tramites_suporte(tramite_cadastrado)
                tramite_cadastrado.id_secundario = id_secundario
                database.session.commit()
                flash('Pedido de suporte realizado com sucesso', 'alert-success')
                return redirect(url_for('lista_suporte'))

            elif int(form_suporte.id_usuario_destino.data) == 1:
                suporte = Suporte(id_tipo_suporte=int(form_suporte.id_tipo_suporte.data),
                                  titulo_suporte=form_suporte.titulo_suporte.data,
                                  id_setor_suporte=int(form_suporte.id_setor_suporte.data),
                                  id_usuario_autor=current_user.id,
                                  id_setor_destino_suporte=int(form_suporte.id_setor_destino_suporte.data),
                                  id_grau_urgencia=int(form_suporte.id_grau_urgencia.data),
                                  visivel=ocultar)
                database.session.add(suporte)
                database.session.commit()
                suporte_cadastrado = Suporte.query.filter_by(titulo_suporte=form_suporte.titulo_suporte.data).first()

                autor = Usuarios.query.filter_by(id=suporte_cadastrado.id_usuario_autor).first()
                destino = Usuarios.query.filter_by(id=suporte_cadastrado.id_usuario_destino).first()

                tramite = TramitesSuporte(id_suporte=suporte_cadastrado.id,
                                          body_tramite=form_suporte.body_tramite.data,
                                          id_autor=current_user.id,
                                          ocultar=ocultar,
                                          id_situacao_tramite=1)

                titulo = cria_titulo_recado_suporte(7)
                body_recado = cria_texto_recado_suporte(id_body=7, titulo_suporte=suporte_cadastrado.titulo_suporte,
                                                        chamado_id=suporte_cadastrado.id)

                post_destino = Posts(identificador=1,
                                     setor=suporte_cadastrado.id_setor_destino_suporte,
                                     id_tipo_recado=5,
                                     id_usuario_autor=1,
                                     titulo=titulo,
                                     body=body_recado)

                post_autor = Posts(identificador=1,
                                   id_usuario_destino=autor.id,
                                   cargo=autor.id_cargo,
                                   setor=autor.id_setor,
                                   id_tipo_recado=2,
                                   id_usuario_autor=1,
                                   titulo=titulo,
                                   body=body_recado)

                database.session.add(post_destino)
                database.session.add(post_autor)
                database.session.add(tramite)
                database.session.commit()
                tramite_cadastrado = TramitesSuporte.query.filter_by(body_tramite=tramite.body_tramite).first()
                tempo.sleep(0.2)
                id_secundario = id_secundario_tabela_tramites_suporte(tramite_cadastrado)
                tramite_cadastrado.id_secundario = id_secundario
                database.session.commit()
                flash('Pedido de suporte realizado com sucesso', 'alert-success')
                return redirect(url_for('desenvolvimento'))

            else:
                flash('Favor contate o setor de TI', 'alert-danger')

    return render_template('criar_chamado_suporte.html', form_suporte=form_suporte)


def pesquisa_todos_chamados_abertos():
    chamados = Suporte.query.filter(Suporte.id_situacao_suporte.notin_([9, 8])).order_by(Suporte.data_ultimo_tramite.desc()).all()
    return chamados


def pesquisa_tramites(pesquisa):
    tramite_alias = aliased(TramitesSuporte)
    suporte_query = Suporte.query \
        .join(tramite_alias, Suporte.id == tramite_alias.id_suporte) \
        .filter((Suporte.titulo_suporte.ilike(f"%{pesquisa}%")) |
                (tramite_alias.body_tramite.ilike(f"%{pesquisa}%"))) \
        .distinct() \
        .all()
    return suporte_query


@app.route('/suporte/chamados/lista', methods=['GET', 'POST'])
@login_required
def lista_suporte():
    form = FormListaSuporte()
    pesquisa = session.get('pesquisa_suporte')

    if form.validate_on_submit():
        session['pesquisa_suporte'] = form.pesquisa.data
        return redirect(url_for('lista_suporte'))


    if pesquisa:

        suporte = pesquisa_tramites(pesquisa)
        session.pop('pesquisa_suporte', None)

        if suporte:

            return render_template('encaminha_lista_suporte.html', form=form, chamados=suporte, usuarios=Usuarios,
                                   setores=Setores, situacoes=SituacoesSuporte)
        else:
            flash('Não foi encontrado nenhum ticket com essa descrição', 'alert-warning')

    chamados = pesquisa_todos_chamados_abertos()
    return render_template('encaminha_lista_suporte.html', form=form, chamados=chamados, usuarios=Usuarios,
                           setores=Setores, situacoes=SituacoesSuporte)


@app.route('/suporte/chamados/pesquisa', methods=['GET', 'POST'])
@login_required
def tickets_suporte():
    form = FormListaSuporte()
    form.id_tipo_suporte.choices = [(tipo.id, tipo.nome_tipo_suporte)
                                    for tipo in TiposSuporte.query.filter_by(situacao=1).order_by(
        TiposSuporte.nome_tipo_suporte).all()]

    form.id_setor_suporte.choices = [(setor.id, setor.nome_setor)
                                     for setor in Setores.query.order_by(Setores.nome_setor).all()]

    form.id_setor_destino_suporte.choices = [(setor.id, setor.nome_setor)
                                             for setor in Setores.query.order_by(Setores.nome_setor).all()]

    form.id_usuario_destino.choices = [(usuario.id, usuario.nome_usuario)
                                       for usuario in
                                       Usuarios.query.filter_by(situacao_usuario=1).order_by(
                                           Usuarios.nome_usuario).all()]

    form.id_usuario_autor.choices = [(usuario.id, usuario.nome_usuario)
                                     for usuario in
                                     Usuarios.query.filter(Usuarios.situacao_usuario == 1)
                                     .order_by(Usuarios.nome_usuario).all()]

    form.id_grau_urgencia.choices = [(grau.id, grau.nome_urgencia) for grau in
                                     GrauUrgencia.query.order_by(GrauUrgencia.id).all()]
    if session.get('pesquisa') == 'select_field':
        suportes_dicts = session.get('suporte', [])
        suportes = [Suporte().from_dict(su_dict) for su_dict in suportes_dicts]
        chamados = suportes
    else:
        chamados = pesquisa_todos_chamados_abertos()  # Removido session.get('pesquisa')
    return render_template('tickets_suporte.html', form=form, chamados=chamados, usuarios=Usuarios, setores=Setores, situacoes=SituacoesSuporte)


@app.route('/suporte/chamados/<id_chamado>', methods=['GET', 'POST'])
@login_required
def chamado_visualizacao(id_chamado):
    suporte = Suporte.query.filter_by(id=id_chamado).first()

    ultimo_tramite = TramitesSuporte.query.filter_by(id_suporte=suporte.id).order_by(
        desc(TramitesSuporte.id_secundario)).first()

    if current_user.id == suporte.id_usuario_destino and suporte.id_situacao_suporte == 1 or suporte.id_situacao_suporte == 3:
        suporte.id_situacao_suporte = 2
        database.session.commit()

    elif suporte.id_situacao_suporte == 5 and ultimo_tramite.id_autor != current_user.id:
        suporte.id_situacao_suporte = 2
        database.session.commit()

    tramites = TramitesSuporte.query.filter_by(id_suporte=id_chamado).order_by(TramitesSuporte.data_cadastro).all()
    x = 1
    y = 0
    for tramite in tramites:
        if not tramite.id_secundario:
            tramite.id_secundario = x
            x +=1
            y = 1
    if y == 1:
        tramites = TramitesSuporte.query.filter_by(id_suporte=id_chamado).order_by(
                    TramitesSuporte.data_cadastro).all()
        database.session.commit()
    form = FormTramitesSuporteResposta()
    form.encerrar.choices = [(situacao.id, situacao.nome_situacao_suporte) for situacao in
                             SituacoesSuporte.query.filter(SituacoesSuporte.id.in_([3, 4, 5, 6, 7, 8, 9])).all()]


    if form.validate_on_submit():
        if not suporte.id_usuario_destino:
            suporte.id_usuario_destino = current_user.id
            database.session.commit()
        if form.ocultar.data:
            ocultar = 0
        else:
            ocultar = 1
        if int(form.encerrar.data) == 3 or int(form.encerrar.data) == 4:
            session['body_suporte_encaminhar'] = form.body_tramite.data
            session['ocultar'] = ocultar
            session['encaminhar'] = form.encerrar.data
            return redirect(url_for('encaminhar_suporte', id_chamado=id_chamado))
        elif int(form.encerrar.data) == 5:

            autor = Usuarios.query.filter_by(id=suporte.id_usuario_autor).first()
            destino = Usuarios.query.filter_by(id=suporte.id_usuario_destino).first()

            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                           body_tramite=form.body_tramite.data,
                                           id_autor=current_user.id,
                                           ocultar=ocultar,
                                           id_situacao_tramite=5,
                                           id_secundario=ultimo_tramite.id_secundario + 1)

            titulo = cria_titulo_recado_suporte(6)
            body_recado = cria_texto_recado_suporte(id_body=6, titulo_suporte=suporte.titulo_suporte,
                                                    chamado_id=suporte.id)

            post_destino = Posts(identificador=1,
                                 id_usuario_destino=destino.id,
                                 cargo=destino.id_cargo,
                                 setor=destino.id_setor,
                                 id_tipo_recado=2,
                                 id_usuario_autor=1,
                                 titulo=titulo,
                                 body=body_recado)

            post_autor = Posts(identificador=1,
                               id_usuario_destino=autor.id,
                               cargo=autor.id_cargo,
                               setor=autor.id_setor,
                               id_tipo_recado=2,
                               id_usuario_autor=1,
                               titulo=titulo,
                               body=body_recado)

            database.session.add(post_destino)
            database.session.add(post_autor)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte respondido com sucesso', 'alert-success')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
        elif int(form.encerrar.data) == 6:
            # Fila de produção
            autor = Usuarios.query.filter_by(id=suporte.id_usuario_autor).first()
            destino = Usuarios.query.filter_by(id=suporte.id_usuario_destino).first()

            suporte.ordem_fila = busca_fila_suporte(destino.id)

            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                           body_tramite=form.body_tramite.data,
                                           id_autor=current_user.id,
                                           ocultar=ocultar,
                                           id_situacao_tramite=6,
                                           id_secundario=ultimo_tramite.id_secundario + 1)

            titulo = cria_titulo_recado_suporte(5)
            body_recado = cria_texto_recado_suporte(id_body=5, titulo_suporte=suporte.titulo_suporte,
                                                    chamado_id=suporte.id)

            post_destino = Posts(identificador=1,
                                 id_usuario_destino=destino.id,
                                 cargo=destino.id_cargo,
                                 setor=destino.id_setor,
                                 id_tipo_recado=2,
                                 id_usuario_autor=1,
                                 titulo=titulo,
                                 body=body_recado)

            post_autor = Posts(identificador=1,
                               id_usuario_destino=autor.id,
                               cargo=autor.id_cargo,
                               setor=autor.id_setor,
                               id_tipo_recado=2,
                               id_usuario_autor=1,
                               titulo=titulo,
                               body=body_recado)

            database.session.add(post_destino)
            database.session.add(post_autor)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte respondido com sucesso', 'alert-success')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
        elif int(form.encerrar.data) == 7:

            autor = Usuarios.query.filter_by(id=suporte.id_usuario_autor).first()
            destino = Usuarios.query.filter_by(id=suporte.id_usuario_destino).first()

            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                           body_tramite=form.body_tramite.data,
                                           id_autor=current_user.id,
                                           ocultar=ocultar,
                                           id_situacao_tramite=7,
                                           id_secundario=ultimo_tramite.id_secundario + 1)

            titulo = cria_titulo_recado_suporte(4)
            body_recado = cria_texto_recado_suporte(id_body=4, titulo_suporte=suporte.titulo_suporte,
                                                    chamado_id=suporte.id)

            post_destino = Posts(identificador=1,
                                 id_usuario_destino=destino.id,
                                 cargo=destino.id_cargo,
                                 setor=destino.id_setor,
                                 id_tipo_recado=2,
                                 id_usuario_autor=1,
                                 titulo=titulo,
                                 body=body_recado)

            post_autor = Posts(identificador=1,
                               id_usuario_destino=autor.id,
                               cargo=autor.id_cargo,
                               setor=autor.id_setor,
                               id_tipo_recado=2,
                               id_usuario_autor=1,
                               titulo=titulo,
                               body=body_recado)

            database.session.add(post_destino)
            database.session.add(post_autor)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte respondido com sucesso', 'alert-success')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
        elif int(form.encerrar.data) == 8:

            autor = Usuarios.query.filter_by(id=suporte.id_usuario_autor).first()
            destino = Usuarios.query.filter_by(id=suporte.id_usuario_destino).first()
            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                           body_tramite=form.body_tramite.data,
                                           id_autor=current_user.id,
                                           ocultar=ocultar,
                                           id_situacao_tramite=8,
                                           id_secundario=ultimo_tramite.id_secundario + 1)

            titulo = cria_titulo_recado_suporte(2)
            body_recado = cria_texto_recado_suporte(id_body=3, titulo_suporte=suporte.titulo_suporte,
                                                    chamado_id=suporte.id)

            post_destino = Posts(identificador=1,
                                 id_usuario_destino=destino.id,
                                 cargo=destino.id_cargo,
                                 setor=destino.id_setor,
                                 id_tipo_recado=2,
                                 id_usuario_autor=1,
                                 titulo=titulo,
                                 body=body_recado)

            post_autor = Posts(identificador=1,
                               id_usuario_destino=autor.id,
                               cargo=autor.id_cargo,
                               setor=autor.id_setor,
                               id_tipo_recado=2,
                               id_usuario_autor=1,
                               titulo=titulo,
                               body=body_recado)

            database.session.add(post_destino)
            database.session.add(post_autor)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte finalizado sem sucesso', 'alert-danger')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
        elif int(form.encerrar.data) == 9:
            autor = Usuarios.query.filter_by(id=suporte.id_usuario_autor).first()
            destino = Usuarios.query.filter_by(id=suporte.id_usuario_destino).first()
            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                           body_tramite=form.body_tramite.data,
                                           id_autor=current_user.id,
                                           ocultar=ocultar,
                                           id_situacao_tramite=9,
                                           id_secundario=ultimo_tramite.id_secundario + 1)

            titulo = cria_titulo_recado_suporte(3)
            body_recado = cria_texto_recado_suporte(id_body=3, titulo_suporte=suporte.titulo_suporte, chamado_id=suporte.id)

            post_destino = Posts(identificador=1,
                         id_usuario_destino=destino.id,
                         cargo=destino.id_cargo,
                         setor=destino.id_setor,
                         id_tipo_recado=2,
                         id_usuario_autor=1,
                         titulo=titulo,
                         body=body_recado)

            post_autor = Posts(identificador=1,
                                 id_usuario_destino=autor.id,
                                 cargo=autor.id_cargo,
                                 setor=autor.id_setor,
                                 id_tipo_recado=2,
                                 id_usuario_autor=1,
                                 titulo=titulo,
                                 body=body_recado)

            database.session.add(post_destino)
            database.session.add(post_autor)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte finalizado sem sucesso', 'alert-success')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
    return render_template('suporte_visualizacao.html', suporte=suporte, tramites=tramites, setores=Setores,
                           usuarios=Usuarios, tipos_suportes=TiposSuporte, situacoes_suporte=SituacoesSuporte,
                           grau_urgencia=GrauUrgencia, form=form, ultimo_tramite=ultimo_tramite, cargos=Cargos)


@app.route('/suporte/chamados/<id_chamado>/encaminhar', methods=['GET', 'POST'])
@login_required
def encaminhar_suporte(id_chamado):
    suporte = Suporte.query.filter_by(id=id_chamado).first()
    form = FormEncaminharSuporte()
    form.usuarios.choices = [(usuario.id, usuario.nome_usuario) for usuario in busca_todos_usuarios()]
    body = session.get('body_suporte_encaminhar')
    ultimo_tramite = TramitesSuporte.query.filter_by(id_suporte=suporte.id).order_by(
        desc(TramitesSuporte.id_secundario)).first()
    if form.validate_on_submit():
        if session.get('encaminhar') == '3':
            usuario_antigo = suporte.id_usuario_destino
            usuario = Usuarios.query.filter_by(id=form.usuarios.data).first()
            suporte.id_usuario_destino = usuario.id
            suporte.id_situacao_suporte = 3
            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                      body_tramite=body,
                                      id_autor=current_user.id,
                                      ocultar=session.get('ocultar'),
                                      id_situacao_tramite=3,
                                      id_secundario=ultimo_tramite.id_secundario + 1)
            titulo = cria_titulo_recado_suporte(1)
            body_recado = cria_texto_recado_suporte(id_body=1, titulo_suporte=suporte.titulo_suporte,
                                                    chamado_id=suporte.id, id_usuario=usuario_antigo)

            post = Posts(identificador=1,
                         id_usuario_destino=usuario.id,
                         cargo=usuario.id_cargo,
                         setor=usuario.id_setor,
                         id_tipo_recado=2,
                         id_usuario_autor=1,
                         titulo=titulo,
                         body=body_recado)
            database.session.add(post)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte encaminhado com sucesso', 'alert-success')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
        if session.get('encaminhar') == '4':

            usuario_antigo = suporte.id_usuario_autor

            usuario = Usuarios.query.filter_by(id=form.usuarios.data).first()
            suporte.id_usuario_autor = usuario.id
            suporte.id_situacao_suporte = 4
            novo_tramite = TramitesSuporte(id_suporte=suporte.id,
                                           body_tramite=body,
                                           id_autor=current_user.id,
                                           ocultar=session.get('ocultar'),
                                           id_situacao_tramite=4,
                                           id_secundario=ultimo_tramite.id_secundario + 1)

            titulo = cria_titulo_recado_suporte(1)
            body_recado = cria_texto_recado_suporte(id_body=2, titulo_suporte=suporte.titulo_suporte,
                                                    chamado_id=suporte.id, id_usuario=usuario_antigo)

            post = Posts(identificador=1,
                         id_usuario_destino=usuario.id,
                         cargo=usuario.id_cargo,
                         setor=usuario.id_setor,
                         id_tipo_recado=2,
                         id_usuario_autor=1,
                         titulo=titulo,
                         body=body_recado)
            database.session.add(post)
            database.session.add(novo_tramite)
            database.session.commit()
            flash('Suporte encaminhado com sucesso', 'alert-success')
            return redirect(url_for('chamado_visualizacao', id_chamado=id_chamado))
    return render_template('encaminhar_suporte.html', grau_urgencia=GrauUrgencia, setores=Setores,
                           form=form, usuarios=Usuarios, tipos_suportes=TiposSuporte,
                           situacoes_suporte=SituacoesSuporte, suporte=suporte)


@app.route('/usuarios')
@login_required
def usuarios():
    return render_template('usuarios.html')


@app.route('/perfil/<id_usuario>')
@login_required
def perfil(id_usuario):
    usuario = Usuarios.query.filter_by(id=id_usuario).first()
    return render_template('perfil.html', id_usuario=id_usuario, usuario=usuario, situacao=Situacoes,
                           setor=Setores, cargo=Cargos, ramal=Ramais, vinculo_ramal=UsuarioRamal, usuarios=Usuarios)


@app.route('/perfil/<int:id_usuario>/editar', methods=['GET', 'POST'])
@login_required
def alterar_senha(id_usuario):
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 5 or int(id_usuario) == current_user.id:
        form = FormAlterarSenha()
        usuario = Usuarios.query.filter_by(id=id_usuario).first()
        if form.validate_on_submit():
            if bcrypt.check_password_hash(usuario.senha, form.senha_atual.data):
                senha = bcrypt.generate_password_hash(form.senha.data).decode('UTF-8')
                usuario.senha = senha
                database.session.commit()
                flash('Senha atualizada com sucesso', 'alert-success')
                return redirect(url_for('perfil', id_usuario=id_usuario))
        return render_template('editar_senha.html', form=form)
    else:
        return redirect(url_for('home'))


@app.route('/home/direção/recadosadmin', methods=['GET', 'POST'])
@login_required
def home_admin():
    if int(session.get('hierarquia_setor')) > 0 or int(session.get('hierarquia_cargo')) >= 8:
        form = FormPesquisaRecadosAdmin()
        if session.get('data_inicio') and session.get('data_fim'):
            data_inicio = datetime.strptime(session.get('data_inicio'), '%Y-%m-%d')
            data_fim = datetime.strptime(session.get('data_fim'), '%Y-%m-%d')
            data_inicio = data_inicio.replace(hour=00,minute=0, second=0)
            data_fim = data_fim.replace(hour=23,minute=59, second=59)
            recados = retorna_posts(data_inicial=data_inicio, data_final=data_fim)
            form.data_inicial.data = data_inicio
            form.data_final.data = data_fim
            session.pop('data_inicio', None)
            session.pop('data_fim', None)
            return render_template('recados_admin.html', recados=recados, form=form, usuarios=Usuarios,
                                   setores=Setores, cargos=Cargos)
        if form.validate_on_submit():
            session['data_inicio'] = form.data_inicial.data.strftime('%Y-%m-%d')
            session['data_fim'] = form.data_final.data.strftime('%Y-%m-%d')
            return redirect(url_for('home_admin'))
        return render_template('recados_admin.html', recados=retorna_posts(), form=form, usuarios=Usuarios, setores=Setores, cargos=Cargos)
    else:
        return redirect(url_for('home'))


@app.route('/home/ferramentasgerais')
@login_required
def ferramentas_gerais():
    return render_template('home_ferramentas_gerais.html', usuarios=Usuarios, setores=Setores, cargos=Cargos)


@app.route('/home/direcao')
@login_required
def direcao():
    return render_template('home_direcao.html', usuarios=Usuarios, setores=Setores, cargos=Cargos)


@app.route('/home/desenvolvimento')
@login_required
def desenvolvimento():
    return render_template('home_desenvolvimento.html',
                           usuarios=Usuarios, setores=Setores, cargos=Cargos)