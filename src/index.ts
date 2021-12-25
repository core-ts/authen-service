import { AuthInfo, AuthResult, CustomJwtToken, DB, Module, Privilege, SqlAuthConfig, SqlConfig, Statement, Status, StatusConf, StringMap, Token, UserAccount, UserInfo, UserRepository, UserStatus } from './auth';

export * from './auth';
export type TokenConf = Token;
export type TokenConfig = Token;
export type StatusConfig = StatusConf;
export type Info = AuthInfo;
export type User = AuthInfo;
export type Result = AuthResult;
export type Account = UserAccount;
export type UserService = UserRepository;
export type Config = SqlAuthConfig;

export function useAuthenticator<T extends AuthInfo>(status: Status,
  check: (user: T) => Promise<AuthResult>,
  generateToken: (payload: any, secret: string, expiresIn: number) => Promise<string | undefined>,
  getPrivileges: (username: string) => Promise<Privilege[]>,
  token: Token,
  payload: StringMap,
  account?: StringMap, repository?: UserRepository,
  lockedMinutes?: number,
  maxPasswordFailed?: number,
  compare?: (v1: string, v2: string) => Promise<boolean>): Authenticator<T> {
  return new Authenticator<T>(status, generateToken, getPrivileges, token, payload, account, repository, compare, lockedMinutes, maxPasswordFailed, check);
}
export const createAuthenticator = useAuthenticator;
export class Authenticator<T extends AuthInfo> {
  constructor(public status: Status,
    public generateToken: <P>(payload: P, secret: string, expiresIn: number) => Promise<string | undefined>,
    public getPrivileges: (userId: string) => Promise<Privilege[]>,
    public token: Token,
    public payload: StringMap,
    public account?: StringMap,
    public repository?: UserRepository,
    public compare?: (v1: string, v2: string) => Promise<boolean>,
    public lockedMinutes?: number,
    public maxPasswordFailed?: number,
    public check?: (user: T) => Promise<AuthResult>) {
    this.authenticate = this.authenticate.bind(this);
  }
  async authenticate(info: T): Promise<AuthResult> {
    let result: AuthResult = { status: this.status.fail };
    const username = info.username;
    const password = info.password;
    if (!username || username === '' || !password || password === '') {
      return result;
    }
    if (this.check) {
      result = await this.check(info);
      if (!result || result.status !== this.status.success && result.status !== this.status.success_and_reactivated) {
        return result;
      }
      if (!this.repository) {
        const tokenExpiredTime0 = addSeconds(new Date(), this.token.expires);
        const payload0 = result.user ? map(result.user, this.payload) : { id: info.username, username: info.username };
        const token0 = await this.generateToken(payload0, this.token.secret, this.token.expires);
        const account0: UserAccount = {};
        account0.token = token0;
        account0.tokenExpiredTime = tokenExpiredTime0;
        result.status = this.status.success;
        result.user = account0;
        return result;
      }
    }
    if (!this.repository) {
      return result;
    }
    const user = await this.repository.getUser(info.username);
    if (!user) {
      result.status = this.status.fail;
      // result.message = 'UserNotExisted';
      return result;
    }
    if (!this.check && this.compare) {
      const valid = await this.compare(password, user.password ? user.password : '');
      if (!valid) {
        result.status = this.status.wrong_password;
        if (this.repository.fail) {
          const isUpdateStatus = await this.repository.fail(user.id, user.failCount);
          if (!isUpdateStatus) {
            result.status = this.status.fail;
            return result;
          }
        } else {
          return result;
        }
      }
      const account1: UserAccount = {};
      result.user = account1;
    }
    if (user.disable) {
      result.status = this.status.disabled;
      return result;
    }
    if (user.suspended) {
      result.status = this.status.suspended;
      return result;
    }
    if (user.failTime && user.failTime instanceof Date && this.lockedMinutes !== undefined && user.failCount !== undefined && this.maxPasswordFailed !== undefined && user.failCount > this.maxPasswordFailed) {
      const lockedUntilTime = addMinutes(user.failTime, this.lockedMinutes);
      const locked = (lockedUntilTime && (subTime(now(), lockedUntilTime) < 0));
      if (locked) {
        result.status = this.status.locked;
        return result;
      }
    }

    let passwordExpiredTime = null;
    if (user.passwordModifiedTime && user.maxPasswordAge && user.maxPasswordAge > 0) {
      passwordExpiredTime = addDays(user.passwordModifiedTime, user.maxPasswordAge);
    }
    if (passwordExpiredTime && subTime(now(), passwordExpiredTime) > 0) {
      result.status = this.status.password_expired;
      return result;
    }
    if (!isValidAccessDate(user.accessDateFrom, user.accessDateTo)) {
      result.status = this.status.disabled;
      return result;
    }
    if (!isValidAccessTime(user.accessTimeFrom, user.accessTimeTo)) {
      result.status = this.status.access_time_locked;
      return result;
    }
    const { tokenExpiredTime, jwtTokenExpires } = setTokenExpiredTime(user, this.token.expires);
    const payload = map(user, this.payload);
    const token = await this.generateToken(payload, this.token.secret, jwtTokenExpires);
    if (user.deactivated) {
      result.status = this.status.success_and_reactivated;
    } else {
      result.status = this.status.success;
    }
    const account = mapAll<UserInfo, UserAccount>(user, this.account);
    account.token = token;
    account.tokenExpiredTime = tokenExpiredTime;

    if (this.getPrivileges) {
      const privileges = await this.getPrivileges(user.id);
      account.privileges = privileges;
    }
    result.user = account;
    if (this.repository.pass) {
      return this.repository.pass(user.id, user.deactivated).then(isStatus => {
        if (isStatus === false) {
          result.status = this.status.fail;
        }
        return result;
      });
    } else {
      return result;
    }
  }
}
/*
export function mapAccount(user: User, account: UserAccount): UserAccount {
  account.id = user.id;
  account.username = user.username;
  account.userType = user.userType;
  account.roles = user.roles;
  if (user.id.length > 0) {
    account.id = user.id;
  }
  if (user.displayName && user.displayName.length > 0) {
    account.displayName = user.displayName;
  }
  if (user.email && user.email.length > 0) {
    account.contact = user.email;
  }
  return account;
}
*/
export function setTokenExpiredTime(user: UserInfo, expires: number): CustomJwtToken {
  if (user.accessTimeTo == null || user.accessTimeFrom == null || user.accessDateFrom == null || user.accessDateTo == null) {
    const x = addSeconds(now(), expires / 1000);
    return { tokenExpiredTime: x, jwtTokenExpires: expires };
  }

  if (before(user.accessTimeTo, user.accessTimeFrom) || equalDate(user.accessTimeTo, user.accessDateFrom)) {
    const tmp = addHours(user.accessTimeTo, 24);
    user.accessDateTo = tmp;
  }

  let tokenExpiredTime: Date = new Date();
  let jwtExpiredTime = 0;

  if (expires > subTime(user.accessTimeTo, now())) {
    tokenExpiredTime = addSeconds(now(), subTime(user.accessTimeTo, now()));
    jwtExpiredTime = subTime(user.accessTimeTo, now()) / 1000;
  } else {
    tokenExpiredTime = addSeconds(now(), expires / 1000);
    jwtExpiredTime = expires;
  }
  return { tokenExpiredTime, jwtTokenExpires: jwtExpiredTime };
}

export function isValidAccessDate(fromDate?: Date, toDate?: Date): boolean {
  const today = now();
  if (fromDate && toDate) {
    const toDateNew = addHours(toDate, 24);
    if (before(fromDate, today) === true || equalDate(fromDate, today) === true && after(toDateNew, toDate) === true) {
      return true;
    }
  } else if (toDate) {
    const toDateNew = addHours(toDate, 24);
    if (after(toDateNew, today) === true) {
      return true;
    }
  } else if (fromDate) {
    if (before(fromDate, today) === true || equalDate(fromDate, today) === true) {
      return true;
    }
  } else {
    return true;
  }
  return false;
}
export function isValidAccessTime(fromTime?: Date, toTime?: Date): boolean {
  const today = now();
  if (fromTime && toTime) {
    if (before(toTime, fromTime) || equalDate(toTime, fromTime)) {
      toTime = addHours(toTime, 24);
    }
    if (before(fromTime, today) || equalDate(fromTime, today) && after(toTime, today) || equalDate(toTime, today)) {
      return true;
    }
  } else if (toTime) {
    if (after(toTime, today) || equalDate(toTime, today)) {
      return true;
    }
    return false;
  } else if (fromTime) {
    if (before(fromTime, today) || equalDate(fromTime, today)) {
      return true;
    }
    return false;
  }
  return true;
}

export function addSeconds(date: Date, number: number): Date {
  const newDate = new Date(date);
  newDate.setSeconds(newDate.getSeconds() + number);
  return newDate;
}
export function addMinutes(date: Date, number: number): Date {
  const newDate = new Date(date);
  newDate.setMinutes(newDate.getMinutes() + number);
  return newDate;
}
export function addHours(date: Date, number: number): Date {
  // return moment(date).add(number, 'hours').toDate();
  const newDate = new Date(date);
  newDate.setHours(newDate.getHours() + number);
  return newDate;
}
export function addDays(date: Date, number: number): Date {
  const newDate = new Date(date);
  newDate.setDate(newDate.getDate() + number);
  return newDate;
}
export function after(date1?: Date, date2?: Date): boolean {
  if (!date1 || !date2) {
    return false;
  }
  if (date1.getTime() - date2.getTime() > 0) {
    return true;
  }
  return false;
}
export function before(date1?: Date, date2?: Date): boolean {
  if (!date1 || !date2) {
    return false;
  }
  if (date1.getTime() - date2.getTime() < 0) {
    return true;
  }
  return false;
}
export function now(): Date {
  return new Date();
}
// return milliseconds
export function subTime(date1: Date, date2: Date): number {
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
export function equalDate(date1?: Date, date2?: Date): boolean {
  if (!date1 || !date2) {
    return true;
  }
  if (date1.getTime() - date2.getTime() === 0) {
    return true;
  }
  return false;
}
export class PrivilegesLoader {
  constructor(public query: <T>(sql: string, args?: any[]) => Promise<T[]>, public sql: string, public count?: number) {
    this.privileges = this.privileges.bind(this);
  }
  privileges(userId: string): Promise<Privilege[]> {
    const p = [userId];
    if (this.count && this.count >= 2) {
      for (let i = 2; i <= this.count; i++) {
        p.push(userId);
      }
    }
    return this.query<Module>(this.sql, [userId]).then(v => {
      if (v && v.length >= 2) {
        if (v[0].permissions !== undefined) {
          return toPrivileges(orPermissions(v));
        }
      }
      return toPrivileges(v);
    });
  }
}
export const PrivilegeService = PrivilegesLoader;
export const PrivilegeRepository = PrivilegesLoader;
export class PrivilegesReader {
  constructor(public query: <T>(sql: string, args?: any[]) => Promise<T[]>, public sql: string) {
    this.privileges = this.privileges.bind(this);
  }
  privileges(): Promise<Privilege[]> {
    return this.query<Module>(this.sql).then(v => toPrivileges(v));
  }
}
export function toPrivileges(m: Module[]): Privilege[] {
  const ps: Module[] = getRoot(m);
  for (const p of ps) {
    getChildren(p, m);
  }
  return ps.sort(subPrivilege);
}
export function getRoot(ms: Module[]): Module[] {
  const ps: Module[] = [];
  for (const m of ms) {
    if (!m.parent || m.parent.length === 0) {
      delete m.parent;
      ps.push(m);
    }
  }
  return ps.sort(subPrivilege);
}
export function getChildren(m: Module, all: Module[]) {
  const children: Privilege[] = [];
  for (const s of all) {
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
export function orPermissions(all: Module[]): Module[] {
  if (all.length <= 1) {
    return all;
  }
  const modules = all.sort(subPrivilegeId);
  const ms: Module[] = [];
  const l = all.length;
  const l1 = l - 1;
  for (let i = 0; i < l1;) {
    for (let j = i + 1; j < l; j++) {
      if (modules[i].id === modules[j].id) {
        // tslint:disable-next-line:no-bitwise
        modules[i].permissions = modules[i].permissions | modules[j].permissions;
        if (j === l1) {
          ms.push(modules[i]);
          i = l1 + 3;
          break;
        }
      } else {
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
export function subPrivilegeId(p1: Privilege, p2: Privilege): number {
  return subString(p1.id, p2.id);
}
export function subPrivilege(p1: Privilege, p2: Privilege): number {
  return sub(p1.sequence, p2.sequence);
}
export function subString(n1?: string, n2?: string): number {
  if (!n1 && !n2) {
    return 0;
  } else if (n1 && n2) {
    return n1.localeCompare(n2);
  } else if (n1) {
    return 1;
  } else if (n2) {
    return -1;
  }
  return 0;
}
export function sub(n1?: number, n2?: number): number {
  if (!n1 && !n2) {
    return 0;
  } else if (n1 && n2) {
    return n1 - n2;
  } else if (n1) {
    return n1;
  } else if (n2) {
    return -n2;
  }
  return 0;
}
export function map<T, R>(obj: T, m: StringMap): R {
  if (!m) {
    return obj as any;
  }
  const mkeys = Object.keys(m);
  const obj2: any = {};
  for (const key of mkeys) {
    let k0 = m[key];
    const v = (obj as any)[k0];
    if (v !== undefined) {
      k0 = key;
      obj2[key] = v;
    }
  }
  return obj2;
}
export const deletedFields = ['password', 'disable', 'deactivated', 'suspended', 'lockedUntilTime', 'successTime', 'failTime', 'failCount', 'passwordModifiedTime', 'maxPasswordAge', 'accessDateFrom', 'accessDateTo', 'accessTimeFrom', 'accessTimeTo'];
export function mapAll<T, R>(obj: T, m?: StringMap): R {
  if (!m) {
    return obj as any;
  }
  const mkeys = Object.keys(m);
  if (mkeys.length === 0) {
    return obj as any;
  }
  const obj2: any = {};
  const keys = Object.keys(obj);
  for (const key of keys) {
    let k0 = m[key];
    if (!k0) {
      k0 = key;
    }
    obj2[k0] = (obj as any)[key];
  }
  for (const f of deletedFields) {
    delete obj2[f];
  }
  return obj2;
}
export function initializeStatus(s?: StatusConf): Status {
  const timeout: number | string = (s && s.timeout ? s.timeout : -1);
  const fail: number | string = (s && s.fail ? s.fail : 0);
  const success: number | string = (s && s.success ? s.success : 1);
  const success_and_reactivated: number | string = (s && s.success_and_reactivated ? s.success_and_reactivated : 1);
  const password_expired: number | string = (s && s.password_expired ? s.password_expired : fail);
  const two_factor_required: number | string = (s && s.two_factor_required ? s.two_factor_required : 2);
  const wrong_password: number | string = (s && s.wrong_password ? s.wrong_password : fail);
  const locked: number | string = (s && s.locked ? s.locked : fail);
  const suspended: number | string = (s && s.suspended ? s.suspended : fail);
  const disabled: number | string = (s && s.disabled ? s.disabled : fail);
  const access_time_locked: number | string = (s && s.access_time_locked ? s.access_time_locked : fail);
  const error: number | string = (s && s.error ? s.error : fail);
  return { timeout, fail, success, success_and_reactivated, password_expired, two_factor_required, wrong_password, locked, suspended, disabled, access_time_locked, error };
}
export function useUserRepository(db: DB, c: SqlConfig): SqlUserRepository {
  return new SqlUserRepository(db, c.sql.query, c.sql.fail, c.sql.pass, c.sql.pass2, c.status, c.statusName, c.maxPasswordAge, c.time);
}
export function getUser(obj: UserInfo, status?: string, s?: UserStatus, maxPasswordAge?: number): UserInfo {
  if (status && status.length > 0) {
    const t = (obj as any)[status];
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
    delete (obj as any)[status];
  }
  if (maxPasswordAge !== undefined && maxPasswordAge > 0 && (!obj.maxPasswordAge || obj.maxPasswordAge < 0)) {
    obj.maxPasswordAge = maxPasswordAge;
  }
  return obj;
}
export const createUserRepository = useUserRepository;
export const createUserService = useUserRepository;
export const useUserService = useUserRepository;
export class SqlUserRepository implements UserRepository {
  public time: boolean;
  constructor(public db: DB, public query: string, public sqlFail?: string, public sqlPass?: string, public sqlPass2?: string, public status?: UserStatus, public statusName?: string, public maxPasswordAge?: number, time?: boolean) {
    this.time = (time !== undefined ? true : false);
  }
  getUser(username: string): Promise<UserInfo | null | undefined> {
    return this.db.query<UserInfo>(this.query, [username]).then(v => !v || v.length <= 0 ? undefined : getUser(v[0], this.statusName, this.status, this.maxPasswordAge));
  }
  fail(userId: string): Promise<boolean> {
    if (!this.sqlFail || this.sqlFail.length === 0) {
      return Promise.resolve(true);
    }
    const ps: any[] = (this.time ? [new Date(), userId] : [userId]);
    return this.db.exec(this.sqlFail, ps).then(n => n > 0);
  }
  pass(userId: string, deactivated?: boolean): Promise<boolean> {
    if (!this.sqlPass || this.sqlPass.length === 0) {
      return Promise.resolve(true);
    }
    if (!this.sqlPass2 || this.sqlPass2.length === 0) {
      if (deactivated && this.status && this.status.activated) {
        const ps: any[] = (this.time ? [new Date(), this.status.activated, userId] : [this.status.activated, userId]);
        return this.db.exec(this.sqlPass, ps).then(n => n > 0);
      } else {
        const ps: any[] = (this.time ? [new Date(), userId] : [userId]);
        return this.db.exec(this.sqlPass, ps).then(n => n > 0);
      }
    }
    if (deactivated && this.status && this.status.activated) {
      const ps1: any[] = (this.time ? [new Date(), userId] : [userId]);
      const s1: Statement = { query: this.sqlPass, params: ps1 };
      const ps2: any[] = (this.time ? [new Date(), this.status.activated, userId] : [this.status.activated, userId]);
      const s2: Statement = { query: this.sqlPass2, params: ps2 };
      return this.db.execBatch([s1, s2]).then(n => n > 0);
    } else {
      const ps: any[] = (this.time ? [new Date(), userId] : [userId]);
      return this.db.exec(this.sqlPass, ps).then(n => n > 0);
    }
  }
}
export const SqlUserService = SqlUserRepository;
