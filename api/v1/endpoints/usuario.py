from typing import List, Optional, Any

from fastapi import APIRouter, status, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from models.usuario_model import UsuarioModel
from schemas.usuario_schema import UsuarioSchemaBase, UsuarioSchemaCreate, UsuarioSchemaUp, UsuarioSchemaArtigos, UsuarioSchemaUpdate
from core.deps import get_session, get_current_user
from core.security import gerar_hash_senha
from core.auth import autenticar, criar_token_acesso


router = APIRouter()


# GET Logado
@router.get('/logado', response_model=UsuarioSchemaBase, description="Verifica as informaçoes do usuario logado atual")
def get_logado(usuario_logado: UsuarioModel = Depends(get_current_user)):
    return usuario_logado


# POST / Signup
@router.post('/signup', status_code=status.HTTP_201_CREATED, response_model=UsuarioSchemaBase, description="Realiza o cadastro de um usuario")
async def post_usuario(usuario: UsuarioSchemaCreate, db: AsyncSession = Depends(get_session)):
    novo_usuario: UsuarioModel = UsuarioModel(nome=usuario.nome, sobrenome=usuario.sobrenome,
                                              email=usuario.email, senha=gerar_hash_senha(usuario.senha), eh_admin=usuario.eh_admin)
    async with db as session:
        try:
            session.add(novo_usuario)
            await session.commit()

            return novo_usuario
        except IntegrityError:
            raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE,
                                detail='Já existe um usuário com este email cadastrado.')


# GET Usuarios
@router.get('/', response_model=List[UsuarioSchemaBase],  description="Retorna a lista de usuarios")
async def get_usuarios(db: AsyncSession = Depends(get_session)):
    async with db as session:
        query = select(UsuarioModel)
        result = await session.execute(query)
        usuarios: List[UsuarioSchemaBase] = result.scalars().unique().all()

        return usuarios


# GET Usuario
@router.get('/{usuario_id}', response_model=UsuarioSchemaArtigos, status_code=status.HTTP_200_OK, description="Retorna as informações de um usuario")
async def get_usuario(usuario_id: int, db: AsyncSession = Depends(get_session)):
    async with db as session:
        query = select(UsuarioModel).filter(UsuarioModel.id == usuario_id)
        result = await session.execute(query)
        usuario: UsuarioSchemaArtigos = result.scalars().unique().one_or_none()

        if usuario:
            return usuario
        else:
            raise HTTPException(detail='Usuário não encontrado.',
                                status_code=status.HTTP_404_NOT_FOUND)


# PUT Usuario
@router.put('/{usuario_id}', response_model=UsuarioSchemaBase, status_code=status.HTTP_202_ACCEPTED, description="Atualiza as informações de um usuário")
async def put_usuario(usuario_id: int, usuario: UsuarioSchemaUpdate, db: AsyncSession = Depends(get_session), usuario_logado: UsuarioModel = Depends(get_current_user)):
    async with db as session:
        query = select(UsuarioModel).filter(UsuarioModel.id == usuario_id)

        if usuario_logado.eh_admin:
            result = await session.execute(query)
        else:
            query = query.filter(UsuarioModel.id == usuario_logado.id)
            result = await session.execute(query)

        usuario_up: UsuarioModel = result.scalars().unique().one_or_none()

        if usuario_up:
            # Atualiza apenas os campos fornecidos
            if usuario.nome is not None:
                usuario_up.nome = usuario.nome
            if usuario.sobrenome is not None:
                usuario_up.sobrenome = usuario.sobrenome
            if usuario.email is not None:
                usuario_up.email = usuario.email
            if usuario.eh_admin is not None and usuario_logado.eh_admin:
                usuario_up.eh_admin = usuario.eh_admin
            if usuario.senha is not None:
                if usuario_logado.id == usuario_id:
                    usuario_up.senha = gerar_hash_senha(usuario.senha)
                else:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                        detail="Você não pode alterar a senha de outro usuário.")

            await session.commit()
            return usuario_up
        else:
            raise HTTPException(detail='Usuário não encontrado.',
                                status_code=status.HTTP_404_NOT_FOUND)


# DELETE usuario
@router.delete('/{usuario_id}', status_code=status.HTTP_204_NO_CONTENT, description="Delete algum usuario caso for admin")
async def delete_usuario(usuario_id: int, db: AsyncSession = Depends(get_session), usuario_logado: UsuarioModel = Depends(get_current_user)):
    async with db as session:
        # Verifica se o usuário logado é um administrador
        if usuario_logado.eh_admin:
            # Busca o usuário com o ID fornecido
            query = select(UsuarioModel).filter(UsuarioModel.id == usuario_id)
            result = await session.execute(query)
            usuario_del: UsuarioSchemaArtigos = result.scalars().unique().one_or_none()

            if usuario_del:
                # Deleta o usuário encontrado
                await session.delete(usuario_del)
                await session.commit()

                return Response(status_code=status.HTTP_204_NO_CONTENT)
            else:
                raise HTTPException(
                    detail='Usuário não encontrado.', status_code=status.HTTP_404_NOT_FOUND)
        else:
            # Se o usuário logado não for administrador, não permite a operação
            raise HTTPException(detail='Permissão negada.',
                                status_code=status.HTTP_403_FORBIDDEN)


# POST Login
@router.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_session)):
    usuario = await autenticar(email=form_data.username, senha=form_data.password, db=db)

    if not usuario:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Dados de acesso incorretos.')

    return JSONResponse(content={"access_token": criar_token_acesso(sub=usuario.id), "token_type": "bearer"}, status_code=status.HTTP_200_OK)
