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
  var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
  return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
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
var __spreadArrays = (this && this.__spreadArrays) || function () {
  for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
  for (var r = Array(s), k = 0, i = 0; i < il; i++)
    for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
      r[k] = a[j];
  return r;
};
Object.defineProperty(exports, "__esModule", { value: true });
var util = require("util");
function useAuthenticator(status, check, generateToken, token, payload, account, repository, getPrivileges, lockedMinutes, maxPasswordFailed, send, expires, codeRepository, compare, hash, hasTwoFactors, gen) {
  return new Authenticator(status, compare, generateToken, token, payload, account, repository, getPrivileges, lockedMinutes, maxPasswordFailed, send, expires, codeRepository, hash, hasTwoFactors, gen, check);
}
exports.useAuthenticator = useAuthenticator;
exports.createAuthenticator = useAuthenticator;
exports.useLogin = useAuthenticator;
exports.useSignin = useAuthenticator;
function swap(m) {
  if (!m) {
    return m;
  }
  var keys = Object.keys(m);
  var values = Object.values(m);
  var l = keys.length;
  var obj = {};
  for (var i = 0; i < l; i++) {
    obj[values[i]] = keys[i];
  }
  return obj;
}
exports.swap = swap;
var Authenticator = (function () {
  function Authenticator(status, compare, generateToken, token, payload, account, repository, getPrivileges, lockedMinutes, maxPasswordFailed, send, expires, codeRepository, hash, hasTwoFactors, gen, check) {
    this.status = status;
    this.compare = compare;
    this.generateToken = generateToken;
    this.token = token;
    this.payload = payload;
    this.repository = repository;
    this.getPrivileges = getPrivileges;
    this.lockedMinutes = lockedMinutes;
    this.maxPasswordFailed = maxPasswordFailed;
    this.send = send;
    this.expires = expires;
    this.codeRepository = codeRepository;
    this.hash = hash;
    this.hasTwoFactors = hasTwoFactors;
    this.check = check;
    this.generate = gen ? gen : generate;
    this.account = swap(account);
    this.authenticate = this.authenticate.bind(this);
    this.login = this.login.bind(this);
    this.signin = this.signin.bind(this);
  }
  Authenticator.prototype.login = function (info) {
    return this.authenticate(info);
  };
  Authenticator.prototype.signin = function (info) {
    return this.authenticate(info);
  };
  Authenticator.prototype.authenticate = function (info) {
    return __awaiter(this, void 0, void 0, function () {
      var s, result, username, password, tokenExpiredTime0, payload0, token0, account0, user, tnow, valid, lockedUntilTime, lockedUntilTime, locked, lockedUntilTime, locked, passwordExpiredTime, contact, twoFactors, sentCode, savedCode, codeExpired, res0, code, validPasscode, _a, expiredTime, expires, payload, token, account, privileges;
      return __generator(this, function (_b) {
        switch (_b.label) {
          case 0:
            s = this.status;
            result = { status: s.fail };
            username = info.username;
            password = info.password;
            if (!username || username === "" || !password || password === "") {
              return [2, result];
            }
            if (!this.check) return [3, 3];
            return [4, this.check(info)];
          case 1:
            result = _b.sent();
            if (!result || (result.status !== s.success && result.status !== s.success_and_reactivated)) {
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
            result.status = s.success;
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
              result.status = s.fail;
              return [2, result];
            }
            tnow = new Date();
            if (!(!this.check && this.compare)) return [3, 8];
            return [4, this.compare(password, user.password ? user.password : "")];
          case 5:
            valid = _b.sent();
            if (!!valid) return [3, 8];
            result.status = s.wrong_password;
            if (!this.repository.fail) return [3, 7];
            lockedUntilTime = void 0;
            if (this.lockedMinutes &&
              user.failCount !== undefined &&
              this.maxPasswordFailed !== undefined &&
              user.failCount >= this.maxPasswordFailed) {
              lockedUntilTime = addMinutes(tnow, this.lockedMinutes);
            }
            return [4, this.repository.fail(user.id, user.failCount, lockedUntilTime)];
          case 6:
            _b.sent();
            return [2, result];
          case 7: return [2, result];
          case 8:
            if (user.lockedUntilTime) {
              if (user.lockedUntilTime.getTime() > tnow.getTime()) {
                result.status = s.locked;
                return [2, result];
              }
            }
            if (user.disable) {
              result.status = s.disabled;
              return [2, result];
            }
            if (user.suspended) {
              result.status = s.suspended;
              return [2, result];
            }
            if (user.lockedUntilTime) {
              lockedUntilTime = user.lockedUntilTime;
              locked = lockedUntilTime && subTime(now(), lockedUntilTime) < 0;
              if (locked) {
                result.status = s.locked;
                return [2, result];
              }
            }
            else if (user.failTime &&
              user.failTime instanceof Date &&
              this.lockedMinutes !== undefined &&
              user.failCount !== undefined &&
              this.maxPasswordFailed !== undefined &&
              user.failCount >= this.maxPasswordFailed) {
              lockedUntilTime = addMinutes(user.failTime, this.lockedMinutes);
              locked = lockedUntilTime && subTime(now(), lockedUntilTime) < 0;
              if (locked) {
                result.status = s.locked;
                return [2, result];
              }
            }
            passwordExpiredTime = null;
            if (user.passwordModifiedTime && user.maxPasswordAge && user.maxPasswordAge > 0) {
              passwordExpiredTime = addDays(user.passwordModifiedTime, user.maxPasswordAge);
            }
            if (passwordExpiredTime && subTime(now(), passwordExpiredTime) > 0) {
              result.status = s.password_expired;
              return [2, result];
            }
            if (!isValidAccessDate(user.accessDateFrom, user.accessDateTo)) {
              result.status = s.disabled;
              return [2, result];
            }
            if (!isValidAccessTime(user.accessTimeFrom, user.accessTimeTo)) {
              result.status = s.access_time_locked;
              return [2, result];
            }
            contact = user.contact ? user.contact : user.email;
            if (!(contact && this.hash && this.expires && this.expires > 0 && this.codeRepository && this.send && this.compare)) return [3, 21];
            twoFactors = user.twoFactors;
            if (!(!twoFactors && this.hasTwoFactors)) return [3, 10];
            return [4, this.hasTwoFactors(user.id)];
          case 9:
            twoFactors = _b.sent();
            _b.label = 10;
          case 10:
            if (!twoFactors) return [3, 21];
            if (!(!info.step || info.step <= 1)) return [3, 16];
            sentCode = this.generate();
            return [4, this.hash(sentCode)];
          case 11:
            savedCode = _b.sent();
            codeExpired = addSeconds(new Date(), this.expires);
            return [4, this.codeRepository.save(user.id, savedCode, codeExpired)];
          case 12:
            res0 = _b.sent();
            if (!(res0 > 0)) return [3, 14];
            return [4, this.send(contact, sentCode, codeExpired, info.username)];
          case 13:
            _b.sent();
            return [2, { status: this.status.two_factor_required }];
          case 14: return [2, { status: this.status.fail }];
          case 15: return [3, 21];
          case 16:
            if (!info.passcode || info.passcode.length === 0) {
              return [2, { status: this.status.fail }];
            }
            return [4, this.codeRepository.load(user.id)];
          case 17:
            code = _b.sent();
            if (!code) {
              return [2, { status: this.status.fail }];
            }
            if (code.expiredAt.getTime() < tnow.getTime()) {
              return [2, { status: this.status.fail }];
            }
            return [4, this.compare(info.passcode, code.code)];
          case 18:
            validPasscode = _b.sent();
            if (!!validPasscode) return [3, 19];
            return [2, { status: this.status.fail }];
          case 19: return [4, this.codeRepository.delete(user.id)];
          case 20:
            _b.sent();
            _b.label = 21;
          case 21:
            _a = setTokenExpiredTime(user, this.token.expires), expiredTime = _a.expiredTime, expires = _a.expires;
            payload = map(user, this.payload);
            return [4, this.generateToken(payload, this.token.secret, expires)];
          case 22:
            token = _b.sent();
            if (user.deactivated) {
              result.status = s.success_and_reactivated;
            }
            else {
              result.status = s.success;
            }
            account = mapAll(user, this.account);
            account.token = token;
            account.tokenExpiredTime = expiredTime;
            if (!this.getPrivileges) return [3, 24];
            return [4, this.getPrivileges(user.id)];
          case 23:
            privileges = _b.sent();
            account.privileges = privileges;
            _b.label = 24;
          case 24:
            result.user = account;
            if (this.repository.pass) {
              return [2, this.repository.pass(user.id, user.deactivated).then(function (isStatus) {
                  if (!isStatus) {
                    result.status = s.fail;
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
exports.LoginService = Authenticator;
exports.SigninService = Authenticator;
function setTokenExpiredTime(user, expires) {
  if (!user.accessTimeTo || !user.accessTimeFrom || !user.accessDateFrom || !user.accessDateTo) {
    var x = addSeconds(now(), expires / 1000);
    return { expiredTime: x, expires: expires };
  }
  if (before(user.accessTimeTo, user.accessTimeFrom) || equalDate(user.accessTimeTo, user.accessDateFrom)) {
    var tmp = addHours(user.accessTimeTo, 24);
    user.accessDateTo = tmp;
  }
  var tokenExpiredTime = new Date();
  var jwtExpiredTime = 0;
  if (expires > Math.abs(subTime(user.accessTimeTo, now()))) {
    tokenExpiredTime = addSeconds(now(), subTime(user.accessTimeTo, now()));
    jwtExpiredTime = Math.abs(subTime(user.accessTimeTo, now())) / 1000;
  }
  else {
    tokenExpiredTime = addSeconds(now(), expires / 1000);
    jwtExpiredTime = expires;
  }
  return { expiredTime: tokenExpiredTime, expires: jwtExpiredTime };
}
exports.setTokenExpiredTime = setTokenExpiredTime;
function isValidAccessDate(fromDate, toDate) {
  var today = now();
  if (fromDate && toDate) {
    var toDateNew = addHours(toDate, 24);
    if (before(fromDate, today) || (equalDate(fromDate, today) && before(toDate, toDateNew))) {
      return true;
    }
  }
  else if (toDate) {
    var toDateNew = addHours(toDate, 24);
    if (before(today, toDateNew)) {
      return true;
    }
  }
  else if (fromDate) {
    if (before(fromDate, today) || equalDate(fromDate, today)) {
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
    if (before(fromTime, today) || (equalDate(fromTime, today) && before(today, toTime)) || equalDate(toTime, today)) {
      return true;
    }
  }
  else if (toTime) {
    if (before(today, toTime) || equalDate(toTime, today)) {
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
  var d = new Date(date);
  d.setSeconds(d.getSeconds() + number);
  return d;
}
exports.addSeconds = addSeconds;
function addMinutes(date, number) {
  var d = new Date(date);
  d.setMinutes(d.getMinutes() + number);
  return d;
}
exports.addMinutes = addMinutes;
function addHours(date, number) {
  var d = new Date(date);
  d.setHours(d.getHours() + number);
  return d;
}
exports.addHours = addHours;
function addDays(date, number) {
  var d = new Date(date);
  d.setDate(d.getDate() + number);
  return d;
}
exports.addDays = addDays;
function before(d1, d2) {
  if (!d1 || !d2) {
    return false;
  }
  if (d1.getTime() - d2.getTime() < 0) {
    return true;
  }
  return false;
}
exports.before = before;
function now() {
  return new Date();
}
exports.now = now;
function subTime(d1, d2) {
  if (d1 && d2) {
    var n1 = d1.getTime();
    var n2 = d2.getTime();
    var x = n1 - n2;
    return x;
  }
  if (d1) {
    return 1;
  }
  if (d2) {
    return -1;
  }
  return 0;
}
exports.subTime = subTime;
function equalDate(d1, d2) {
  if (!d1 || !d2) {
    return true;
  }
  if (d1.getTime() - d2.getTime() === 0) {
    return true;
  }
  return false;
}
exports.equalDate = equalDate;
var PrivilegesLoader = (function () {
  function PrivilegesLoader(query, sql, count) {
    this.query = query;
    this.sql = sql;
    this.count = count;
    this.privileges = this.privileges.bind(this);
  }
  PrivilegesLoader.prototype.privileges = function (userId) {
    var p = [userId];
    if (this.count && this.count >= 2) {
      for (var i = 2; i <= this.count; i++) {
        p.push(userId);
      }
    }
    return this.query(this.sql, [userId]).then(function (v) {
      if (v && v.length >= 2) {
        if (v[0].permissions !== undefined) {
          return toPrivileges(orPermissions(v));
        }
      }
      return toPrivileges(v);
    });
  };
  return PrivilegesLoader;
}());
exports.PrivilegesLoader = PrivilegesLoader;
exports.PrivilegeService = PrivilegesLoader;
exports.PrivilegeRepository = PrivilegesLoader;
var PrivilegesReader = (function () {
  function PrivilegesReader(query, sql) {
    this.query = query;
    this.sql = sql;
    this.privileges = this.privileges.bind(this);
  }
  PrivilegesReader.prototype.privileges = function () {
    return this.query(this.sql).then(function (v) { return toPrivileges(v); });
  };
  return PrivilegesReader;
}());
exports.PrivilegesReader = PrivilegesReader;
function toPrivileges(m) {
  var ps = getRoot(m);
  for (var _i = 0, ps_1 = ps; _i < ps_1.length; _i++) {
    var p = ps_1[_i];
    getChildren(p, m);
  }
  return ps.sort(subPrivilege);
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
function orPermissions(all) {
  if (all.length <= 1) {
    return all;
  }
  var modules = all.sort(subPrivilegeId);
  var ms = [];
  var l = all.length;
  var l1 = l - 1;
  for (var i = 0; i < l1;) {
    for (var j = i + 1; j < l; j++) {
      if (modules[i].id === modules[j].id) {
        modules[i].permissions = modules[i].permissions | modules[j].permissions;
        if (j === l1) {
          ms.push(modules[i]);
          i = l1 + 3;
          break;
        }
      }
      else {
        ms.push(modules[i]);
        i = j;
      }
    }
  }
  if (l >= 2) {
    if (modules[l1].id !== modules[l1 - 1].id) {
      ms.push(modules[l1]);
    }
  }
  return ms;
}
exports.orPermissions = orPermissions;
function subPrivilegeId(p1, p2) {
  return subString(p1.id, p2.id);
}
exports.subPrivilegeId = subPrivilegeId;
function subPrivilege(p1, p2) {
  return sub(p1.sequence, p2.sequence);
}
exports.subPrivilege = subPrivilege;
function subString(n1, n2) {
  if (!n1 && !n2) {
    return 0;
  }
  else if (n1 && n2) {
    return n1.localeCompare(n2);
  }
  else if (n1) {
    return 1;
  }
  else if (n2) {
    return -1;
  }
  return 0;
}
exports.subString = subString;
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
  if (mkeys.length === 0) {
    return obj;
  }
  var obj2 = {};
  var keys = Object.keys(m);
  for (var _i = 0, keys_1 = keys; _i < keys_1.length; _i++) {
    var key = keys_1[_i];
    var k0 = m[key];
    if (!k0) {
      k0 = key;
    }
    var v = obj[key];
    if (v !== undefined) {
      obj2[k0] = v;
    }
  }
  return obj2;
}
exports.map = map;
exports.deletedFields = [
  "password",
  "disable",
  "deactivated",
  "suspended",
  "lockedUntilTime",
  "successTime",
  "failTime",
  "failCount",
  "passwordModifiedTime",
  "maxPasswordAge",
  "accessDateFrom",
  "accessDateTo",
  "accessTimeFrom",
  "accessTimeTo",
  "twoFactors",
  "history",
];
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
  for (var _i = 0, keys_2 = keys; _i < keys_2.length; _i++) {
    var key = keys_2[_i];
    var k0 = m[key];
    if (!k0) {
      k0 = key;
    }
    obj2[k0] = obj[key];
  }
  for (var _a = 0, deletedFields_1 = exports.deletedFields; _a < deletedFields_1.length; _a++) {
    var f = deletedFields_1[_a];
    delete obj2[f];
  }
  return obj2;
}
exports.mapAll = mapAll;
function initializeStatus(s) {
  var timeout = s && s.timeout ? s.timeout : -1;
  var fail = s && s.fail ? s.fail : 0;
  var success = s && s.success ? s.success : 1;
  var success_and_reactivated = s && s.success_and_reactivated ? s.success_and_reactivated : 1;
  var password_expired = s && s.password_expired ? s.password_expired : fail;
  var two_factor_required = s && s.two_factor_required ? s.two_factor_required : 2;
  var wrong_password = s && s.wrong_password ? s.wrong_password : fail;
  var locked = s && s.locked ? s.locked : fail;
  var suspended = s && s.suspended ? s.suspended : fail;
  var disabled = s && s.disabled ? s.disabled : fail;
  var access_time_locked = s && s.access_time_locked ? s.access_time_locked : fail;
  var error = s && s.error ? s.error : fail;
  return {
    timeout: timeout,
    fail: fail,
    success: success,
    success_and_reactivated: success_and_reactivated,
    password_expired: password_expired,
    two_factor_required: two_factor_required,
    wrong_password: wrong_password,
    locked: locked,
    suspended: suspended,
    disabled: disabled,
    access_time_locked: access_time_locked,
    error: error,
  };
}
exports.initializeStatus = initializeStatus;
exports.fields = [
  "userId",
  "displayName",
  "lockedUntilTime",
  "successTime",
  "failTime",
  "failCount",
  "passwordModifiedTime",
  "maxPasswordAge",
  "userType",
  "accessDateFrom",
  "accessDateTo",
  "accessTimeFrom",
  "accessTimeTo",
  "twoFactors",
  "dateFormat",
  "timeFormat",
  "imageURL",
];
function createMap() {
  var m = {};
  for (var _i = 0, fields_1 = exports.fields; _i < fields_1.length; _i++) {
    var s = fields_1[_i];
    m[s.toLowerCase()] = s;
  }
  return m;
}
exports.createMap = createMap;
function getUser(obj, status, s, maxPasswordAge) {
  if (status && status.length > 0) {
    var t = obj[status];
    if (t !== undefined && t != null && s) {
      if (s.deactivated !== undefined && t === s.deactivated) {
        obj.deactivated = true;
      }
      if (s.suspended !== undefined && t === s.suspended) {
        obj.suspended = true;
      }
      if (s.disable !== undefined && t === s.disable) {
        obj.disable = true;
      }
    }
    delete obj[status];
  }
  if (maxPasswordAge !== undefined && maxPasswordAge > 0 && (!obj.maxPasswordAge || obj.maxPasswordAge < 0)) {
    obj.maxPasswordAge = maxPasswordAge;
  }
  return obj;
}
exports.getUser = getUser;
function useUserRepository(db, c, m) {
  var n = m ? m : createMap();
  return new SqlUserRepository(db, c.db, c.query, c.userStatus, n);
}
exports.useUserRepository = useUserRepository;
exports.createUserRepository = useUserRepository;
exports.createUserService = useUserRepository;
exports.useUserService = useUserRepository;
var SqlUserRepository = (function () {
  function SqlUserRepository(db, conf, query, status, mp) {
    this.db = db;
    this.conf = conf;
    this.query = query;
    this.status = status;
    this.map = mp;
    this.id = !this.conf.id || this.conf.id.length === 0 ? "id" : this.conf.id;
    this.password = conf.password ? conf.password : conf.user;
    this.getUser = this.getUser.bind(this);
    this.pass = this.pass.bind(this);
    this.fail = this.fail.bind(this);
  }
  SqlUserRepository.prototype.getUser = function (username) {
    var _this = this;
    var c = this.conf;
    return this.db.query(this.query, [username], this.map).then(function (v) {
      return !v || v.length <= 0 ? undefined : getUser(v[0], c.status, _this.status, c.maxPasswordAge);
    });
  };
  SqlUserRepository.prototype.pass = function (userId, deactivated) {
    var c = this.conf;
    var pass = {};
    if (c.successTime.length > 0) {
      pass[c.successTime] = new Date();
    }
    if (c.failTime.length > 0) {
      pass[c.failTime] = null;
    }
    if (c.failCount.length > 0) {
      pass[c.failCount] = 0;
    }
    if (c.lockedUntilTime.length > 0) {
      pass[c.lockedUntilTime] = null;
    }
    var keys = Object.keys(pass);
    var l = keys.length;
    if (l === 0) {
      return Promise.resolve(true);
    }
    if (!deactivated || !this.status || c.status.length === 0) {
      var stmt = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId);
      return this.db.exec(stmt.query, stmt.params).then(function (v) { return (v > 0 ? true : false); });
    }
    else {
      var activated = this.status.activated;
      if (activated && activated !== "") {
        if (c.user === c.password || c.password === undefined) {
          pass[c.status] = activated;
          var stmt = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId);
          return this.db.exec(stmt.query, stmt.params).then(function (v) { return (v > 0 ? true : false); });
        }
        else {
          var stmt1 = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId);
          var query = "update " + c.user + " set " + c.status + " = " + this.db.param(1) + " where " + this.id + " = " + this.db.param(2);
          var params = [activated, userId];
          var stmt2 = { query: query, params: params };
          return this.db.execBatch([stmt1, stmt2], true).then(function (v) { return (v > 0 ? true : false); });
        }
      }
      else {
        var stmt = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId);
        return this.db.exec(stmt.query, stmt.params).then(function (v) { return (v > 0 ? true : false); });
      }
    }
  };
  SqlUserRepository.prototype.fail = function (userId, failCount, lockedUntilTime) {
    var c = this.conf;
    var pass = {};
    if (c.failTime.length > 0) {
      pass[c.failTime] = new Date();
    }
    if (c.failCount.length > 0 && failCount !== undefined) {
      pass[c.failCount] = failCount + 1;
    }
    if (lockedUntilTime !== undefined && c.lockedUntilTime.length > 0) {
      pass[c.lockedUntilTime] = lockedUntilTime;
    }
    var keys = Object.keys(pass);
    var l = keys.length;
    if (keys.length === 0) {
      return Promise.resolve(true);
    }
    var stmt = buildUpdate(pass, this.db.param);
    var query = "update " + this.password + " set " + stmt.query + " where " + this.id + " = " + this.db.param(l + 1);
    var params = [];
    if (stmt.params && stmt.params.length > 0) {
      for (var _i = 0, _a = stmt.params; _i < _a.length; _i++) {
        var pr = _a[_i];
        params.push(pr);
      }
    }
    params.push(userId);
    return this.db.exec(query, params).then(function (v) { return (v > 0 ? true : false); });
  };
  return SqlUserRepository;
}());
exports.SqlUserRepository = SqlUserRepository;
function buildUpdatePassword(pass, buildParam, table, idName, id) {
  var stmt = buildUpdate(pass, buildParam);
  var k = stmt.params ? stmt.params.length + 1 : 1;
  var query = "update " + table + " set " + stmt.query + " where " + idName + " = " + buildParam(k);
  var params = [];
  if (stmt.params && stmt.params.length > 0) {
    for (var _i = 0, _a = stmt.params; _i < _a.length; _i++) {
      var pr = _a[_i];
      params.push(pr);
    }
  }
  params.push(id);
  stmt.query = query;
  stmt.params = params;
  return stmt;
}
exports.buildUpdatePassword = buildUpdatePassword;
function buildUpdate(obj, buildParam) {
  var keys = Object.keys(obj);
  var cols = [];
  var params = [];
  var o = obj;
  var i = 1;
  for (var _i = 0, keys_3 = keys; _i < keys_3.length; _i++) {
    var key = keys_3[_i];
    var v = o[key];
    if (v != null) {
      cols.push(key + " = " + buildParam(i++));
      params.push(v);
    }
    else if (v == null) {
      cols.push(key + " = null");
    }
  }
  var query = cols.join(",");
  return { query: query, params: params };
}
exports.buildUpdate = buildUpdate;
exports.SqlUserService = SqlUserRepository;
function generate(length) {
  if (!length) {
    length = 6;
  }
  return padLeft(Math.floor(Math.random() * Math.floor(Math.pow(10, length) - 1)).toString(), length, "0");
}
exports.generate = generate;
function padLeft(str, length, pad) {
  if (str.length >= length) {
    return str;
  }
  var str2 = str;
  while (str2.length < length) {
    str2 = pad + str2;
  }
  return str2;
}
exports.padLeft = padLeft;
var MailSender = (function () {
  function MailSender(sendMail, from, body, subject) {
    this.sendMail = sendMail;
    this.from = from;
    this.body = body;
    this.subject = subject;
    this.send = this.send.bind(this);
  }
  MailSender.prototype.send = function (to, passcode, expireAt) {
    var diff = Math.abs(Math.round((Date.now() - expireAt.getTime()) / 1000 / 60));
    var body = util.format.apply(util, __spreadArrays([this.body], [passcode, diff]));
    var msg = {
      to: to,
      from: this.from,
      subject: this.subject,
      html: body,
    };
    return this.sendMail(msg);
  };
  return MailSender;
}());
exports.MailSender = MailSender;
exports.CodeMailSender = MailSender;
