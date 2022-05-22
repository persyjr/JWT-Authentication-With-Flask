import React, { useContext } from "react";
import { Context } from "../store/appContext";
import { useHistory } from "react-router-dom";
import "../../styles/home.css";

import { Card, Row, Container, Column } from "react-bootstrap";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";

export const Login = () => {
  const { store, actions } = useContext(Context);
  const navigate = useHistory();

  function login(event) {
    // Previene el comportamiento por defecto, evitando que la pagina se recargue
    event.preventDefault();
    // Se crea un objeto "FormData" con los datos del formulario
    let data = new FormData(event.target);
    // Se obtiene el nuevo item del formulario
    let email = data.get("email");
    let password = data.get("password");

    actions
      .login(email, password)
      .then((resp) => {
        if (resp.code == 200) navigate.push("/");
        else console.log("Problema en el acceso de usuario: ", resp);
      })
      .catch((error) => {
        console.log("Error en el registro: ", error);
      });
  }

  return (
    <Container>
      <Row>
        <Card>
          <h1>Acceso</h1>
          <Form onSubmit={login}>
            <Form.Group className="mb-3" controlId="formBasicEmail">
              <Form.Label>Email address</Form.Label>
              <Form.Control
                type="email"
                placeholder="Enter email"
                name="email"
                required
              />
              <Form.Text className="text-muted">
                We'll never share your email with anyone else.
              </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3" controlId="formBasicPassword">
              <Form.Label>Password</Form.Label>
              <Form.Control
                type="password"
                placeholder="Password"
                name="password"
                required
              />
            </Form.Group>

            <Button variant="primary" type="submit">
              Submit
            </Button>
          </Form>
        </Card>
      </Row>
    </Container>
  );
};
