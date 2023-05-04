# Brief example of authentication with `Token` in Node JS using `JWT`🌐.

#### About the project
This project presents a very simple example of how to handle login authentications via `token` in Node JS with Express using [Jason Web Token](https://jwt.io/) (JWT). It makes use of a small database in `Json` format that is loaded in memory to use the default user data. This project focuses on business logic and data manipulation (**does not include a frontend**). 


As additional data:
1. Module system used:  **` ECMAScript Modules `** ‼️
2. The VS Code extension ` Thunder Client ` is used for http requests.
3. A small database in Json format in the file `bbdd.js`, this is loaded **in memory** to manipulate it by the operations.

#### Libraries
- `Nodemon` : To avoid having to restart the server every time the server is changed 
-  `Express` : This project uses the Node.js express library to handle HTTP requests and responses.
- `Dotenv` : For manipulation of environment variables (*see the .env.example file to know which environment variables are needed*)
- `Jose` : For operations related to the generation of the tokens. ([More information about the library](https://www.npmjs.com/package/jose))

#### How to use
1. Download or clone the project with git.
2. Create the `.env` file following the attached `.env.example file`.
3. Install the necessary libraries using the `npm install` command.
4. Run the project with the `npm run dev` command.
---

  <p align="center">
    <strong>
    Thanks for using this project! If you have any problems or suggestions, feel free to create an issue on GitHub.
    </strong>
  <p>


