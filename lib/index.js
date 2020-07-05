"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
  function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
  return new (P || (P = Promise))(function (resolve, reject) {
    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
    function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
  var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
  return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
  function verb(n) { return function (v) { return step([n, v]); }; }
  function step(op) {
    if (f) throw new TypeError("Generator is already executing.");
    while (_) try {
      if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
      if (y = 0, t) op = [op[0] & 2, t.value];
      switch (op[0]) {
        case 0: case 1: t = op; break;
        case 4: _.label++; return { value: op[1], done: false };
        case 5: _.label++; y = op[1]; op = [0]; continue;
        case 7: op = _.ops.pop(); _.trys.pop(); continue;
        default:
          if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
          if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
          if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
          if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
          if (t[2]) _.ops.pop();
          _.trys.pop(); continue;
      }
      op = body.call(thisArg, _);
    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
  }
};
Object.defineProperty(exports, "__esModule", { value: true });
function useAuthenticator(status, check, generateToken, getPrivileges, token, payload, account, repository, lockedMinutes, maxPasswordFailed, compare) {
  return new Authenticator(status, generateToken, getPrivileges, token, payload, account, repository, compare, lockedMinutes, maxPasswordFailed, check);
}
exports.useAuthenticator = useAuthenticator;
exports.createAuthenticator = useAuthenticator;
var Authenticator = (function () {
  function Authenticator(status, generateToken, getPrivileges, token, payload, account, repository, compare, lockedMinutes, maxPasswordFailed, check) {
    this.status = status;
    this.generateToken = generateToken;
    this.getPrivileges = getPrivileges;
    this.token = token;
    this.payload = payload;
    this.account = account;
    this.repository = repository;
    this.compare = compare;
    this.lockedMinutes = lockedMinutes;
    this.maxPasswordFailed = maxPasswordFailed;
    this.check = check;
    this.authenticate = this.authenticate.bind(this);
  }
  Authenticator.prototype.authenticate = function (info) {
    return __awaiter(this, void 0, void 0, function () {
      var result, username, password, tokenExpiredTime0, payload0, token0, account0, user, valid, isUpdateStatus, account1, lockedUntilTime, locked, passwordExpiredTime, _a, tokenExpiredTime, jwtTokenExpires, payload, token, account, privileges;
      var _this = this;
      return __generator(this, function (_b) {
        switch (_b.label) {
          case 0:
            result = { status: this.status.fail };
            username = info.username;
            password = info.password;
            if (!username || username === '' || !password || password === '') {
              return [2, result];
            }
            if (!this.check) return [3, 3];
            return [4, this.check(info)];
          case 1:
            result = _b.sent();
            if (!result || result.status !== this.status.success && result.status !== this.status.success_and_reactivated) {
              return [2, result];
            }
            if (!!this.repository) return [3, 3];
            tokenExpiredTime0 = addSeconds(new Date(), this.token.expires);
            payload0 = result.user ? map(result.user, this.payload) : { id: info.username, username: info.username };
            return [4, this.generateToken(payload0, this.token.secret, this.token.expires)];
          case 2:
            token0 = _b.sent();
            account0 = {};
            account0.token = token0;
            account0.tokenExpiredTime = tokenExpiredTime0;
            result.status = this.status.success;
            result.user = account0;
            return [2, result];
          case 3:
            if (!this.repository) {
              return [2, result];
            }
            return [4, this.repository.getUser(info.username)];
          case 4:
            user = _b.sent();
            if (!user) {
              result.status = this.status.fail;
              return [2, result];
            }
            if (!(!this.check && this.compare)) return [3, 9];
            return [4, this.compare(password, user.password ? user.password : '')];
          case 5:
            valid = _b.sent();
            if (!!valid) return [3, 8];
            result.status = this.status.wrong_password;
            if (!this.repository.fail) return [3, 7];
            return [4, this.repository.fail(user.id, user.failCount)];
          case 6:
            isUpdateStatus = _b.sent();
            if (!isUpdateStatus) {
              result.status = this.status.fail;
              return [2, result];
            }
            return [3, 8];
          case 7: return [2, result];
          case 8:
            account1 = {};
            result.user = account1;
            _b.label = 9;
          case 9:
            if (user.disable) {
              result.status = this.status.disabled;
              return [2, result];
            }
            if (user.suspended) {
              result.status = this.status.suspended;
              return [2, result];
            }
            if (user.failTime && user.failTime instanceof Date && this.lockedMinutes !== undefined && user.failCount !== undefined && this.maxPasswordFailed !== undefined && user.failCount > this.maxPasswordFailed) {
              lockedUntilTime = addMinutes(user.failTime, this.lockedMinutes);
              locked = (lockedUntilTime && (subTime(now(), lockedUntilTime) < 0));
              if (locked) {
                result.status = this.status.locked;
                return [2, result];
              }
            }
            passwordExpiredTime = null;
            if (user.passwordModifiedTime && user.maxPasswordAge && user.maxPasswordAge > 0) {
              passwordExpiredTime = addDays(user.passwordModifiedTime, user.maxPasswordAge);
            }
            if (passwordExpiredTime && subTime(now(), passwordExpiredTime) > 0) {
              result.status = this.status.password_expired;
              return [2, result];
            }
            if (!isValidAccessDate(user.accessDateFrom, user.accessDateTo)) {
              result.status = this.status.disabled;
              return [2, result];
            }
            if (!isValidAccessTime(user.accessTimeFrom, user.accessTimeTo)) {
              result.status = this.status.access_time_locked;
              return [2, result];
            }
            _a = setTokenExpiredTime(user, this.token.expires), tokenExpiredTime = _a.tokenExpiredTime, jwtTokenExpires = _a.jwtTokenExpires;
            payload = map(user, this.payload);
            return [4, this.generateToken(payload, this.token.secret, jwtTokenExpires)];
          case 10:
            token = _b.sent();
            if (user.deactivated) {
              result.status = this.status.success_and_reactivated;
            }
            else {
              result.status = this.status.success;
            }
            account = mapAll(user, this.account);
            account.token = token;
            account.tokenExpiredTime = tokenExpiredTime;
            if (!this.getPrivileges) return [3, 12];
            return [4, this.getPrivileges(user.id)];
          case 11:
            privileges = _b.sent();
            account.privileges = privileges;
            _b.label = 12;
          case 12:
            result.user = account;
            if (this.repository.pass) {
              return [2, this.repository.pass(user.id, user.deactivated).then(function (isStatus) {
                if (isStatus === false) {
                  result.status = _this.status.fail;
                }
                return result;
              })];
            }
            else {
              return [2, result];
            }
            return [2];
        }
      });
    });
  };
  return Authenticator;
}());
exports.Authenticator = Authenticator;
function setTokenExpiredTime(user, expires) {
  if (user.accessTimeTo == null || user.accessTimeFrom == null || user.accessDateFrom == null || user.accessDateTo == null) {
    var x = addSeconds(now(), expires / 1000);
    return { tokenExpiredTime: x, jwtTokenExpires: expires };
  }
  if (before(user.accessTimeTo, user.accessTimeFrom) || equalDate(user.accessTimeTo, user.accessDateFrom)) {
    var tmp = addHours(user.accessTimeTo, 24);
    user.accessDateTo = tmp;
  }
  var tokenExpiredTime = new Date();
  var jwtExpiredTime = 0;
  if (expires > subTime(user.accessTimeTo, now())) {
    tokenExpiredTime = addSeconds(now(), subTime(user.accessTimeTo, now()));
    jwtExpiredTime = subTime(user.accessTimeTo, now()) / 1000;
  }
  else {
    tokenExpiredTime = addSeconds(now(), expires / 1000);
    jwtExpiredTime = expires;
  }
  return { tokenExpiredTime: tokenExpiredTime, jwtTokenExpires: jwtExpiredTime };
}
exports.setTokenExpiredTime = setTokenExpiredTime;
function isValidAccessDate(fromDate, toDate) {
  var today = now();
  if (fromDate && toDate) {
    var toDateNew = addHours(toDate, 24);
    if (before(fromDate, today) === true || equalDate(fromDate, today) === true && after(toDateNew, toDate) === true) {
      return true;
    }
  }
  else if (toDate) {
    var toDateNew = addHours(toDate, 24);
    if (after(toDateNew, today) === true) {
      return true;
    }
  }
  else if (fromDate) {
    if (before(fromDate, today) === true || equalDate(fromDate, today) === true) {
      return true;
    }
  }
  else {
    return true;
  }
  return false;
}
exports.isValidAccessDate = isValidAccessDate;
function isValidAccessTime(fromTime, toTime) {
  var today = now();
  if (fromTime && toTime) {
    if (before(toTime, fromTime) || equalDate(toTime, fromTime)) {
      toTime = addHours(toTime, 24);
    }
    if (before(fromTime, today) || equalDate(fromTime, today) && after(toTime, today) || equalDate(toTime, today)) {
      return true;
    }
  }
  else if (toTime) {
    if (after(toTime, today) || equalDate(toTime, today)) {
      return true;
    }
    return false;
  }
  else if (fromTime) {
    if (before(fromTime, today) || equalDate(fromTime, today)) {
      return true;
    }
    return false;
  }
  return true;
}
exports.isValidAccessTime = isValidAccessTime;
function addSeconds(date, number) {
  var newDate = new Date(date);
  newDate.setSeconds(newDate.getSeconds() + number);
  return newDate;
}
exports.addSeconds = addSeconds;
function addMinutes(date, number) {
  var newDate = new Date(date);
  newDate.setMinutes(newDate.getMinutes() + number);
  return newDate;
}
exports.addMinutes = addMinutes;
function addHours(date, number) {
  var newDate = new Date(date);
  newDate.setHours(newDate.getHours() + number);
  return newDate;
}
exports.addHours = addHours;
function addDays(date, number) {
  var newDate = new Date(date);
  newDate.setDate(newDate.getDate() + number);
  return newDate;
}
exports.addDays = addDays;
function after(date1, date2) {
  if (!date1 || !date2) {
    return false;
  }
  if (date1.getTime() - date2.getTime() > 0) {
    return true;
  }
  return false;
}
exports.after = after;
function before(date1, date2) {
  if (!date1 || !date2) {
    return false;
  }
  if (date1.getTime() - date2.getTime() < 0) {
    return true;
  }
  return false;
}
exports.before = before;
function now() {
  return new Date();
}
exports.now = now;
function subTime(date1, date2) {
  if (date1 && date2) {
    return Math.abs((date1.getTime() - date2.getTime()));
  }
  if (date1) {
    return 1;
  }
  if (date2) {
    return -1;
  }
  return 0;
}
exports.subTime = subTime;
function equalDate(date1, date2) {
  if (!date1 || !date2) {
    return true;
  }
  if (date1.getTime() - date2.getTime() === 0) {
    return true;
  }
  return false;
}
exports.equalDate = equalDate;
var PrivilegeRepository = (function () {
  function PrivilegeRepository(query, sql, count) {
    this.query = query;
    this.sql = sql;
    this.count = count;
    this.privileges = this.privileges.bind(this);
  }
  PrivilegeRepository.prototype.privileges = function (userId) {
    var p = [userId];
    if (this.count && this.count >= 2) {
      for (var i = 2; i <= this.count; i++) {
        p.push(userId);
      }
    }
    return this.query(this.sql, [userId]).then(function (v) { return toPrivileges(v); });
  };
  return PrivilegeRepository;
}());
exports.PrivilegeRepository = PrivilegeRepository;
exports.PrivilegeService = PrivilegeRepository;
var PrivilegesLoader = (function () {
  function PrivilegesLoader(query, sql) {
    this.query = query;
    this.sql = sql;
    this.privileges = this.privileges.bind(this);
  }
  PrivilegesLoader.prototype.privileges = function () {
    return this.query(this.sql).then(function (v) { return toPrivileges(v); });
  };
  return PrivilegesLoader;
}());
exports.PrivilegesLoader = PrivilegesLoader;
function toPrivileges(m) {
  var ps = getRoot(m);
  for (var _i = 0, ps_1 = ps; _i < ps_1.length; _i++) {
    var p = ps_1[_i];
    getChildren(p, m);
  }
  return ps;
}
exports.toPrivileges = toPrivileges;
function getRoot(ms) {
  var ps = [];
  for (var _i = 0, ms_1 = ms; _i < ms_1.length; _i++) {
    var m = ms_1[_i];
    if (!m.parent || m.parent.length === 0) {
      delete m.parent;
      ps.push(m);
    }
  }
  return ps.sort(subPrivilege);
}
exports.getRoot = getRoot;
function getChildren(m, all) {
  var children = [];
  for (var _i = 0, all_1 = all; _i < all_1.length; _i++) {
    var s = all_1[_i];
    if (s.parent === m.id) {
      delete s.parent;
      children.push(s);
      getChildren(s, all);
    }
  }
  if (children.length > 0) {
    children.sort(subPrivilege);
    m.children = children;
  }
}
exports.getChildren = getChildren;
function subPrivilege(p1, p2) {
  return sub(p1.sequence, p2.sequence);
}
exports.subPrivilege = subPrivilege;
function sub(n1, n2) {
  if (!n1 && !n2) {
    return 0;
  }
  else if (n1 && n2) {
    return n1 - n2;
  }
  else if (n1) {
    return n1;
  }
  else if (n2) {
    return -n2;
  }
  return 0;
}
exports.sub = sub;
function map(obj, m) {
  if (!m) {
    return obj;
  }
  var mkeys = Object.keys(m);
  var obj2 = {};
  for (var _i = 0, mkeys_1 = mkeys; _i < mkeys_1.length; _i++) {
    var key = mkeys_1[_i];
    var k0 = m[key];
    var v = obj[k0];
    if (v !== undefined) {
      k0 = key;
      obj2[key] = v;
    }
  }
  return obj2;
}
exports.map = map;
function mapAll(obj, m) {
  if (!m) {
    return obj;
  }
  var mkeys = Object.keys(m);
  if (mkeys.length === 0) {
    return obj;
  }
  var obj2 = {};
  var keys = Object.keys(obj);
  for (var _i = 0, keys_1 = keys; _i < keys_1.length; _i++) {
    var key = keys_1[_i];
    var k0 = m[key];
    if (!k0) {
      k0 = key;
    }
    obj2[k0] = obj[key];
  }
  return obj2;
}
exports.mapAll = mapAll;
function initializeStatus(s) {
  var timeout = (s && s.timeout ? s.timeout : -1);
  var fail = (s && s.fail ? s.fail : 0);
  var success = (s && s.success ? s.success : 1);
  var success_and_reactivated = (s && s.success_and_reactivated ? s.success_and_reactivated : 1);
  var password_expired = (s && s.password_expired ? s.password_expired : fail);
  var two_factor_required = (s && s.two_factor_required ? s.two_factor_required : 2);
  var wrong_password = (s && s.wrong_password ? s.wrong_password : fail);
  var locked = (s && s.locked ? s.locked : fail);
  var suspended = (s && s.suspended ? s.suspended : fail);
  var disabled = (s && s.disabled ? s.disabled : fail);
  var access_time_locked = (s && s.access_time_locked ? s.access_time_locked : fail);
  var error = (s && s.error ? s.error : fail);
  return { timeout: timeout, fail: fail, success: success, success_and_reactivated: success_and_reactivated, password_expired: password_expired, two_factor_required: two_factor_required, wrong_password: wrong_password, locked: locked, suspended: suspended, disabled: disabled, access_time_locked: access_time_locked, error: error };
}
exports.initializeStatus = initializeStatus;
function useUserRepository(db, c) {
  return new SqlUserRepository(db, c.sql.query, c.sql.fail, c.sql.pass, c.sql.pass2, c.status, c.statusName, c.maxPasswordAge, c.time);
}
exports.useUserRepository = useUserRepository;
exports.createUserRepository = useUserRepository;
exports.createUserService = useUserRepository;
exports.useUserService = useUserRepository;
var SqlUserRepository = (function () {
  function SqlUserRepository(db, query, sqlFail, sqlPass, sqlPass2, status, statusName, maxPasswordAge, time) {
    this.db = db;
    this.query = query;
    this.sqlFail = sqlFail;
    this.sqlPass = sqlPass;
    this.sqlPass2 = sqlPass2;
    this.status = status;
    this.statusName = statusName;
    this.maxPasswordAge = maxPasswordAge;
    this.time = (time !== undefined ? true : false);
  }
  SqlUserRepository.prototype.getUser = function (username) {
    var _this = this;
    return this.db.query(this.query, [username]).then(function (v) {
      if (!v || v.length <= 0) {
        return undefined;
      }
      else {
        var obj = v[0];
        if (_this.statusName && _this.statusName.length > 0) {
          var s = obj[_this.statusName];
          if (s !== undefined && s != null && _this.status) {
            if (_this.status.deactivated !== undefined && s === _this.status.deactivated) {
              obj.deactivated = true;
            }
            if (_this.status.suspended !== undefined && s === _this.status.suspended) {
              obj.suspended = true;
            }
            if (_this.status.disable !== undefined && s === _this.status.disable) {
              obj.disable = true;
            }
          }
          delete obj[_this.statusName];
        }
        if (_this.maxPasswordAge !== undefined && _this.maxPasswordAge > 0 && (!obj.maxPasswordAge || obj.maxPasswordAge < 0)) {
          obj.maxPasswordAge = _this.maxPasswordAge;
        }
        return obj;
      }
    });
  };
  SqlUserRepository.prototype.fail = function (userId) {
    if (!this.sqlFail || this.sqlFail.length === 0) {
      return Promise.resolve(true);
    }
    var ps = (this.time ? [new Date(), userId] : [userId]);
    return this.db.exec(this.sqlFail, ps).then(function (n) { return n > 0; });
  };
  SqlUserRepository.prototype.pass = function (userId, deactivated) {
    if (!this.sqlPass || this.sqlPass.length === 0) {
      return Promise.resolve(true);
    }
    if (!this.sqlPass2 || this.sqlPass2.length === 0) {
      if (deactivated && this.status && this.status.activated) {
        var ps = (this.time ? [new Date(), this.status.activated, userId] : [this.status.activated, userId]);
        return this.db.exec(this.sqlPass, ps).then(function (n) { return n > 0; });
      }
      else {
        var ps = (this.time ? [new Date(), userId] : [userId]);
        return this.db.exec(this.sqlPass, ps).then(function (n) { return n > 0; });
      }
    }
    if (deactivated && this.status && this.status.activated) {
      var ps1 = (this.time ? [new Date(), userId] : [userId]);
      var s1 = { query: this.sqlPass, params: ps1 };
      var ps2 = (this.time ? [new Date(), this.status.activated, userId] : [this.status.activated, userId]);
      var s2 = { query: this.sqlPass2, params: ps2 };
      return this.db.execBatch([s1, s2]).then(function (n) { return n > 0; });
    }
    else {
      var ps = (this.time ? [new Date(), userId] : [userId]);
      return this.db.exec(this.sqlPass, ps).then(function (n) { return n > 0; });
    }
  };
  return SqlUserRepository;
}());
exports.SqlUserRepository = SqlUserRepository;
exports.SqlUserService = SqlUserRepository;