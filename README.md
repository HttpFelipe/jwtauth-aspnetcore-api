# JWTAuth ASP.NET Core API

<img src="https://miro.medium.com/v2/resize:fit:1358/1*rwXpcs52WE3ZpujqcPLZZg.png">

Este é um projeto que implementa autenticação baseada em tokens JWT (JSON Web Tokens) em uma API ASP.NET Core. O projeto contém duas controllers.

# Controllers

  - AuthenticationController: Responsável pelas funcionalidades de registro e login de usuários do sistema, confirmação de email, geração e renovação de tokens JWT.

  - TeamsController: Para demonstração das funcionalidades da AuthenticationController, esta é responsável por realizar o CRUD de times esportivos.

# Funcionalidades

O projeto possui as seguintes funcionalidades:

  - Registro de Usuário: Os usuários podem se registrar fornecendo um endereço de email e uma senha. O sistema verifica se o email já está em uso antes de criar um novo usuário.

  - Confirmação de Email: Após o registro, um email de confirmação é enviado ao usuário com um link para confirmar o endereço de email. A confirmação é necessária antes que o usuário possa fazer login na aplicação.

  - Login: Os usuários podem fazer login fornecendo seu email e senha registrados. Se as credenciais forem válidas e o email estiver confirmado, um token JWT e um refresh token são gerados.

  - Proteção de Rotas: As rotas da TeamsController são protegidas com autenticação. Para acessá-las, o usuário deve incluir o token JWT nos cabeçalhos da requisição.

  - Renovação de Token: Os usuários podem solicitar a renovação do token JWT para estender o período de autenticação sem a necessidade de fazer login novamente.

# Configuração



O projeto utiliza o SQLite como banco de dados para fins de desenvolvimento. Antes de executar a aplicação, é necessário executar as migrações para criar o banco de dados. 

Para fazer isso, execute os seguintes comandos:

    git clone https://github.com/HttpFelipe/jwtauth-aspnetcore-api.git 

E após navegar até o diretório do projeto, execute os comandos para adicionar e aplicar a migration

    dotnet ef migrations add InitialCreate

    dotnet ef database update
Será necessário também adicionar a secret no arquivo appsettings.Development.json em "JwtConfig": "secret_here".

    "JwtConfig": {
    "Secret": "secret_here",
    "ExpiryTimeFrame": "00:01:00"
    }
Para o envio dos emails de confirmação, é utilizado o <a href="https://ethereal.email/">Etheral Email</a> para fins de desenvolvimento. É possível utilizar qualquer outro serviço de envio de emails, 
realizando as devidas alterações no método SendEmail. Caso utilize o Etheral Email, basta criar o email e substituir as credenciais nos locais apontados como
"Email from Ehereal Email" e "Password from Etheral Email" presentes na AuthenticationController.

# Endpoints Disponíveis

    POST /api/authentication/register: Registra um novo usuário. Requer um objeto JSON contendo email e password.

    GET /api/authentication/confirmemail: Confirma o email do usuário. Requer os parâmetros userId e code na URL.

    POST /api/authentication/login: Realiza o login do usuário. Requer um objeto JSON contendo email e password.

    POST /api/authentication/refreshtoken: Renova o token de autenticação. Requer um objeto JSON contendo token e refreshToken.
    

    GET /api/teams: Obtém todos os times cadastrados no sistema. Requer autenticação com token JWT.

    GET /api/teams/{id}: Obtém informações detalhadas sobre um time específico. Requer autenticação com token JWT.

    POST /api/teams: Cadastra um novo time no sistema. Requer autenticação com token JWT. Requer um objeto JSON contendo informações do time.

    PUT /api/teams/{id}: Atualiza as informações de um time existente. Requer autenticação com token JWT. Requer um objeto JSON contendo as informações atualizadas do time.

    DELETE /api/teams/{id}: Remove um time do sistema. Requer autenticação com token JWT.
