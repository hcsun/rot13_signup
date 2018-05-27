This is an exercise to demonstrate how to build an backend application using Python.

The results are in the following page:

* [SignUp page](https://hello-world-203309.appspot.com/signup)

This page demonstrates how to receive a form and verify the inputs.
It also shows how to interact with the Datastore and how to use hash function to store the password safely.

It will verify the user input using simple rules.
If the user input is valid, it will generate a record in the Datastore for later login process.

* [Login page](https://hello-world-203309.appspot.com/login)

This page shows how to use cookie to maintain the login information.

Once a valid user has signed up, the user can use this page to test the login function.
A manual [logout](https://hello-world-203309.appspot.com/logout) will be needed by entering this URL.
One can check if a logout is successful by looking the `user_id` cookie value.

* [Blog page](https://hello-world-203309.appspot.com/blog)

The page will interact with the database and show the most recent 10 posts.


* [ROT13 page](https://hello-world-203309.appspot.com/rot13)
The page will do a simple Caesar cipher to the user input.