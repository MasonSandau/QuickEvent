# Write up coming soon

Default password, tokens, and usernames are all placeholders

Comments also coming soon

# Concept

The idea behind this is taking names to create a function list is tedious by doing it via text and messages. So me and @chase wanted a simplier way that can be done via a webapp so a person doens't have to go through everything themselves.

# Front end

Front end was created in html using different style choices. I wanted to create something clean and simple so anyone can use it and expand it to their needs. Style sheet uses jsdelivr for styling to keep it simple and use its built in styles. Only html is used for front end rendering.

# Back end

Back end, being my cup of tea, is written in python using flask for handling all data base interactions. 

Web server: The backend webserver uses python and flask to host all interactions. We use flask to handle all post requests as well as 

Data base: Data is all stored in csv's and handled with pythons general file handler.


# Todo

[+] Add main landing page for admin panel as well... perchance

[~] Add a name section for security per date

[~] Add a random name selector for security

[-] Add info tab about development and contact info

[+] Impliment rate limiting (limit 3 names per user, admin is able to remove limit)

# Limitations/Security flaws

# Credits

Front end style sheet: https://github.com/jsdelivr/jsdelivr (https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css).
Some backend functions generated via chatGPT and adapted for our use.
Flask for all backend web handling: https://github.com/pallets/flask
Chase Aspengreen for security, and other back end/front end functions.
