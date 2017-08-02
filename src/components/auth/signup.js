import React, { Component } from 'react';
import { reduxForm } from 'redux-form';
import * as actions from '../../actions';

class SignUp extends Component {
  handleFormSubmit(formProps) {
    //Call action creator to sign up the user!
    this.props.signupUser(formProps);
  }

  renderAlert() {
    if (this.props.errorMessage) {
      return (
        <div className="alert alert-danger">
          <strong>Oops!</strong> {this.props.errorMessage}
        </div>
      );
    }
  }

  render() {
    const { handleSubmit, fields: { username, password,confirmpassword}} = this.props;
    var errorcolor = {
      color:'red'
    };
    return (
      <div>
      <form onSubmit={handleSubmit(this.handleFormSubmit.bind(this))}>
        <fieldset className="form-group">
          <label>Email:</label>
          <input {...username} className="form-control" />
          {username.touched && username.error && <div className="error" style={errorcolor}>{username.error}</div>}
        </fieldset>
        <fieldset className="form-group">
          <label>Password:</label>
          <input {...password} type="password" className="form-control" />
          {password.touched && password.error && <div className="error" style={errorcolor}>{password.error}</div>}
        </fieldset>
        <fieldset className="form-group">
          <label>Confirm Password:</label>
          <input {...confirmpassword} type="password" className="form-control" />
          {confirmpassword.touched && confirmpassword.error && <div className="error" style={errorcolor}>{confirmpassword.error}</div>}
        </fieldset>
        {this.renderAlert()}
        <button action="submit" className="btn btn-primary">Sign Up</button>
      </form>
      </div>
    );
  }
}

function validate(formProps) {
  const errors = {};

  if(!formProps.username) {
    errors.username = 'Please enter an username';
  }

  if(!formProps.password) {
    errors.password = 'Please enter password';
  }

  if(!formProps.confirmpassword) {
    errors.confirmpassword = 'Please confirm password';
  }

  if(formProps.password !== formProps.confirmpassword) {
    errors.password = 'Passwords must match!';
  }

  return errors;
}

function mapStateToProps(state) {
  return { errorMessage: state.auth.error };
}

export default reduxForm({
  validate,
  form: 'signup',
  fields: ['username', 'password','confirmpassword']
}, mapStateToProps, actions)(SignUp);
