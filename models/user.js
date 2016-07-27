var pg = require('pg');
var bcrypt = require('bcrypt');

var SALT_WORK_FACTOR = 10;

var config = {
  database: 'passport',//pulls from postgres db
  port: 5432,
  max: 10,
  idleTimeoutMillis: 30000
};

var pool = new pg.Pool(config);


//function finds username based on input in psdb
function findByUsername(username, callback){
  pool.connect(function(err, client, done){
    if(err){
      done();
      return callback(err);
    }
    //sql syntax to select from 'users' table to find username
    client.query('SELECT * FROM users WHERE username = $1',[username], function(err, result){
      if(err){
        done();
        return callback(err);
      }
      callback(null, result.rows[0]);
      done();
    });
  });
}


//registering a new username and password
function create(username, password, callback){
  //encrypts password
  bcrypt.hash(password, SALT_WORK_FACTOR, function(err, hash){
    pool.connect(function(err, client, done){
      if(err){
        done();
        return callback(err);
      }
      //sql syntax to insert into table both username and password a whole new entry
      client.query('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username;', [username, hash], function(err, result){
        if (err){
          done();
          return callback(err);
        }
        callback(null, result.rows[0]);
        done();
      });
    });
  });
}

//this function checks existing password in table and confirms if they match
function comparePassword(username, candidatePassword, callback){
  //must call findusername function to find associated password
  findByUsername(username, function(err, user){
    if(err){
      return callback(err);
    }
    bcrypt.compare(candidatePassword, user.password, function(err, isMatch){
      if(err){
        console.log(err);
        callback(err);
      } else {
        console.log('isMatch', isMatch);
        callback(null, isMatch, user);
      };
    });
  });
}

function findById(id, callback){
  pool.connect(function(err, client, done){
    if(err){
      done();
      return callback(err);
    }
    client.query('SELECT * FROM users WHERE id = $1',[id], function(err, result){
      if(err){
        done();
        return callback(err);
      }
      callback(null, result.rows[0]);
      done();
    });
  });
}

//exports to server
module.exports = {
  findByUsername: findByUsername,
  findById: findById,
  create: create,
  comparePassword: comparePassword
};
