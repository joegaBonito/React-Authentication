import React, {Component} from 'react';
import {connect} from 'react-redux';
import * as actions from '../actions';

class Admin extends Component {

  componentWillMount() {
    this.props.fetchMessage();
  }

  render() {
    return (
      <div>
      Only the authorized user can view this page
        {this.props.message}
      </div>
    );
  }
}

function mapStateToProps(state) {
  return {
    message:state.auth.message
  };
}

export default connect(mapStateToProps,actions) (Admin);
