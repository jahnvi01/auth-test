import React, { Component } from "react";
import { Redirect } from "react-router-dom";
import AuthService from "../services/auth.service";

export default class Profile extends Component {
    constructor(props) {
        super(props);

        this.state = {
            redirect: null,
            userReady: false,
            currentUser: { username: "" },
        };
    }

    componentDidMount() {
        const currentUser = AuthService.getCurrentUser();

        if (!currentUser) this.setState({ redirect: "/home" });
        this.setState({ currentUser: currentUser, userReady: true });
    }

    render() {
        if (this.state.redirect) {
            return <Redirect to={this.state.redirect} />;
        }

        const { currentUser } = this.state;

        return (
            <div className="container">
                {this.state.userReady ? (
                    <div>
                        <header className="jumbotron">
                            <h3>
                                <strong>{currentUser.username}</strong> Profile
                            </h3>
                        </header>
                        {currentUser.profileImg && <img src={currentUser.profileImg} width="250" height="250" />}
                        <br />
                        <br />
                        <p>
                            <strong>Token:</strong> {currentUser.accessToken.substring(0, 20)} ...{" "}
                            {currentUser.accessToken.substr(currentUser.accessToken.length - 20)}
                        </p>
                        <p>
                            <strong>Id:</strong> {currentUser.id}
                        </p>
                        <p>
                            <strong>Email:</strong> {currentUser.email}
                        </p>
                    </div>
                ) : null}
            </div>
        );
    }
}
