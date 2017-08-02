import axios from 'axios';
import {browserHistory} from 'react-router';
import {AUTH_USER, AUTH_ERROR, UNAUTH_USER, FETCH_MESSAGE} from './types';
import jwtDecode from 'jwt-decode';

const ROOT_URL = `http://localhost:9007`;

export function signinUser({username, password}) {
  return function (dispatch) {
    //Submit email/password to the server
    axios.post(`${ROOT_URL}/auth`, {username,password})
    .then(response => {
      //If request is good...
      //-Update state to indicate user is authenticated
      dispatch({type:AUTH_USER});
      //-Save the JWT token in local storage. localStorage is object available on windows, so it does not have to be imported.
      localStorage.setItem('token',response.data.token);
      //-redirect to the route '/feature'
      browserHistory.push('/feature');
    })
    .catch(() => {
      //If request is bad...
      //-Show an error to the user
      dispatch(authError("Bad Login Info"));
    })
  };
}

export function signoutUser() {
    localStorage.removeItem('token');
    return {
      type:UNAUTH_USER
    };
}

export function signupUser({username,password}) {
  return function (dispatch) {
  axios.post(`${ROOT_URL}/signup`,{username,password})
  .then(response => {
    //If request is good...
    //-Update state to indicate user is authenticated
    dispatch({type:AUTH_USER});
    //-Save the JWT token in local storage. localStorage is object available on windows, so it does not have to be imported.
    localStorage.setItem('token',response.data.token);
    //-redirect to the route '/feature'
    browserHistory.push('/feature');
  })
  .catch(error =>
    //If request is bad...
    //-Show an error to the user
    dispatch(authError(error.response.data.error)));
  }
}

export function authError(error) {
  return {
    type:AUTH_ERROR,
    payload: error
  };
}

export function fetchMessage() {
  return function(dispatch) {
    axios.get(`${ROOT_URL}`, {headers:{authorization:localStorage.getItem('token')}})
    .then(response =>{
    dispatch({
      type:FETCH_MESSAGE,
      payload:response.data.message
    });
    });
  }
}

export function routeToAdmin() {
  return function(dispatch) {
    axios.get(`${ROOT_URL}/admin`, {headers:{authorization:localStorage.getItem('token')}})
      .then(response => {
      browserHistory.push('/admin');
    }
  ).catch(error =>
    //If request is bad...
    //-Show an error to the user
    dispatch(authError(error.response.data.error))
  );
  }
}
