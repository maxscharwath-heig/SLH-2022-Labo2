# SLH Labo 2
> Maxime Scharwath

## How to use
First you need to complete the .env file with your own credentials. 
You can use the `template.env` file as a template.

### Available Oauth2 providers
#### Google
You need to create a project on the [Google Cloud Platform](https://console.cloud.google.com/).
Then you need to create a new OAuth2 client ID and download the credentials file.
Dont forget to set the redirect URI to `http://localhost:8000/_oauth`.
#### Github
You need to create a new OAuth2 app on [https://github.com/settings/applications/new](https://github.com/settings/applications/new).
Like for Google, you need to set redirect URI to `http://localhost:8000/_oauth`.

### SMTP server
You can use the mock SMTP server provided by [MailHog](https://github.com/mailhog/MailHog).
Just run the ```docker-compose up``` command and you will have a SMTP server running on port 1025 and 
a web interface on port 8025.

### Run the application
You can run the application with the following command:
```bash
docker-compose up
cargo run
```

## Conclusion and next steps
One thing to enhance is the oauth authentication.
For example, currently we store authentication method in the database we have only two methods:
- Password
- Oauth

We could store the provider name in the database and use it to redirect the user to the correct provider.
Because currently, if the user has an account with Google with the same email as the Github account, we
can not know which provider to use and the both providers will connect to the same account.
