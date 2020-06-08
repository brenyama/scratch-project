import React, { Component, useState, useEffect } from 'react';
import { connect } from 'react-redux';
import { NavLink } from 'react-router-dom';
import { login } from '../actions/actions';
import { useDispatch } from 'react-redux';


// redirect tag 

const LoginContainer = () => {
  // hook in place of mapDispatchToProps
  const dispatch = useDispatch();
  // useState hook to hold form data
  const [isFetch, setIsFetch] = useState(false);
  const [fields, setFields] = useState({
    username: '',
    password: '',
  });

  const handleClick = (e) => {
    const targetName = e.target.name;
    const value = e.target.value;
    setFields({
      ...fields,
      [targetName]: value
    })
  }

  // **************need real data, need to uncomment line 41 and delete 44-49 *************
  const fetchLogin = () => {
    setIsFetch(true)
  }
  // useEffect(() => {
  //   // object to send in fetch request
  //   const reqData = { 
  //     username: fields.username,
  //     password: fields.password
  //   }
  //   if(isFetch === true){
  //   fetch('/api/', {
  //     method: 'GET',
  //     headers: {
  //       'content-type': 'application/json',
  //     },
  //     body: JSON.stringify(reqData)})
  //     .then((res) => {
  //       // return res.json();
  //     // })
  //     // .then((data) => {
  //       // dummy data for test
  //         const data = {
  //           user: {
  //             _id: 1,
  //             account_name: 'tom',
  //         },
  //           projects: [{
  //             _id: 1,
  //             title: 'Not specified',
  //           }, {           
  //             _id: 2,
  //             title: 'Project 1',
  //           }],
  //           categories: [{
  //             _id: 1,
  //             title: 'Coding',
  //           }, {
  //             _id: 2,
  //             title: 'Debug',
  //           }, {
  //             _id: 3,
  //             title: 'Meetings',
  //           }, {
  //             _id: 4,
  //             title: 'QA',
  //           }, {
  //             _id: 5,
  //             title: 'Code Review',
  //           }, {
  //             _id: 6,
  //             title: 'Reasearch',
  //           }, {
  //             _id: 7,
  //             title: 'Write Documentation',
  //           }, {
  //             _id: 7,
  //             title: 'Other',
  //           }],
  //           timerHistory: [{
  //             time_spent: 5000,
  //             updated_at: new Date().toString(),
  //             category_id: 3,
  //             project_id: 2,
  //           }, {
  //             time_spent: 4000,
  //             updated_at: new Date().toString(),
  //             category_id: 1,
  //             project_id: 2,
  //           }, {
  //             time_spent: 2000,
  //             updated_at: new Date().toString(),
  //             category_id: 3,
  //             project_id: 1,
  //           }, {
  //             time_spent: 4000,
  //             updated_at: new Date().toString(),
  //             category_id: 2,
  //             project_id: 2,
  //           }]
  //         }
  //         const payload = {};
  //         payload.user = data.user;
  //         payload.projects = data.projects;
  //         payload.categories = data.categories;
  //         payload.timerActivity = data.timerHistory;
  //         return payload;
  
  //     })
  //     .then((payload)=> dispatch(login(payload))
  //        setIsFetch(false)
  //     )
  //     .catch((err) => console.log('Login get login: ERROR: ', err));
  //   }
  // })

    return (
      <div id="mainDiv">  
        <div id='nav'>
          <div id='logo'>Tracker</div>
          <a>
            <button type="button" id="log-out" className="button">
              Log Out
            </button>
          </a>
        </div>
        <div id="form">
          <h1 className="site-name" id="site-name-log">
            Login
          </h1>
          <input
            id="username"
            name="username"
            type="text"
            placeholder="Username"
            className="info"
            value={fields.username}
            onChange={handleClick}
          />
          <input 
            id="password" 
            name="password" 
            type="password"
            placeholder="Password"
            value={fields.password}
            onChange={handleClick} 
          />
          {/* when back end is working an rediresting to user page this nav link need to be deleted */}
          <NavLink to="/user">
            <button type="button" id="log-in" className="button" onClick={fetchLogin}>
              Log In
            </button>
          </NavLink>
          <p>Login with <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Logo.png" height="20px"/> <img src="https://image.flaticon.com/icons/svg/25/25231.svg" width="25px" height="25px"/></p>
        </div>
        <div id="no-log-in">
          <div id="forgot" >Don't have an account?</div>
          <NavLink to="signup">
            <button type="button" id="sign-up" className="button">
              Sign Up
            </button>
          </NavLink>
        </div>
    </div>
    );
}

export default LoginContainer;
