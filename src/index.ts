import * as util from "util"
import {
  Account,
  CustomToken,
  DB,
  DBConfig,
  Module,
  Privilege,
  Result,
  SqlAuthConfig,
  Statement,
  Status,
  StatusConf,
  StringMap,
  User,
  UserInfo,
  UserRepository,
  UserStatus,
} from "./auth"
export * from "./auth"

export interface Passcode {
  expiredAt: Date
  code: string
}
export interface CodeRepository<ID> {
  save(id: ID, passcode: string, expireAt: Date): Promise<number>
  load(id: ID): Promise<Passcode | undefined | null>
  delete(id: ID): Promise<number>
}
export function useAuthenticator<T extends User, ID>(
  status: Status,
  check: (user: T) => Promise<Result>,
  account?: StringMap,
  repository?: UserRepository<ID>,
  getPrivileges?: (userId: ID) => Promise<Privilege[]>,
  lockedMinutes?: number,
  maxPasswordFailed?: number,
  send?: (to: string, passcode: string, expireAt: Date, params?: any) => Promise<boolean>,
  expires?: number,
  codeRepository?: CodeRepository<ID>,
  compare?: (v1: string, v2: string) => Promise<boolean>,
  hash?: (plaintext: string) => Promise<string>,
  hasTwoFactors?: (userId: ID) => Promise<boolean>,
  gen?: () => string,
): Authenticator<T, ID> {
  return new Authenticator<T, ID>(
    status,
    compare,
    account,
    repository,
    getPrivileges,
    lockedMinutes,
    maxPasswordFailed,
    send,
    expires,
    codeRepository,
    hash,
    hasTwoFactors,
    gen,
    check,
  )
}
export const createAuthenticator = useAuthenticator
export const useLogin = useAuthenticator
export const useSignin = useAuthenticator
export function swap(m?: StringMap): StringMap | undefined {
  if (!m) {
    return m
  }
  const keys = Object.keys(m)
  const values = Object.values(m)
  const l = keys.length
  const obj: StringMap = {}
  for (let i = 0; i < l; i++) {
    obj[values[i]] = keys[i]
  }
  return obj
}
export class Authenticator<T extends User, ID> {
  constructor(
    public status: Status,
    public compare: ((v1: string, v2: string) => Promise<boolean>) | undefined,
    account?: StringMap,
    public repository?: UserRepository<ID>,
    public getPrivileges?: (userId: ID) => Promise<Privilege[]>,
    public lockedMinutes?: number,
    public maxPasswordFailed?: number,
    public send?: (to: string, passcode: string, expireAt: Date, params?: any) => Promise<boolean>,
    public expires?: number,
    public codeRepository?: CodeRepository<ID>,
    public hash?: (plaintext: string) => Promise<string>,
    public hasTwoFactors?: (userId: ID) => Promise<boolean>,
    gen?: () => string,
    public check?: (user: T) => Promise<Result>,
  ) {
    this.generate = gen ? gen : generate
    this.account = swap(account)
    this.authenticate = this.authenticate.bind(this)
    this.login = this.login.bind(this)
    this.signin = this.signin.bind(this)
  }
  account?: StringMap
  generate: () => string
  login(info: T): Promise<Result> {
    return this.authenticate(info)
  }
  signin(info: T): Promise<Result> {
    return this.authenticate(info)
  }
  async authenticate(info: T): Promise<Result> {
    const s = this.status
    let result: Result = { status: s.fail }
    const username = info.username
    const password = info.password
    if (!username || username === "" || !password || password === "") {
      return result
    }
    if (this.check) {
      result = await this.check(info)
      if (!result || (result.status !== s.success && result.status !== s.success_and_reactivated)) {
        return result
      }
      if (!this.repository) {
        const account0: Account = {}
        result.status = s.success
        result.user = account0
        return result
      }
    }
    if (!this.repository) {
      return result
    }
    const user = await this.repository.getUser(info.username)
    if (!user) {
      result.status = s.fail
      // result.message = 'UserNotExisted';
      return result
    }
    const tnow = new Date()
    if (!this.check && this.compare) {
      const valid = await this.compare(password, user.password ? user.password : "")
      if (!valid) {
        result.status = s.wrong_password
        if (this.repository.fail) {
          let lockedUntilTime: Date | undefined
          if (this.lockedMinutes && user.failCount !== undefined && this.maxPasswordFailed !== undefined && user.failCount >= this.maxPasswordFailed) {
            lockedUntilTime = addMinutes(tnow, this.lockedMinutes)
          }
          await this.repository.fail(user.id, user.failCount, lockedUntilTime)
          return result
        } else {
          return result
        }
      }
    }
    if (user.lockedUntilTime) {
      if (user.lockedUntilTime.getTime() > tnow.getTime()) {
        result.status = s.locked
        return result
      }
    }
    if (user.disable) {
      result.status = s.disabled
      return result
    }
    if (user.suspended) {
      result.status = s.suspended
      return result
    }
    if (user.lockedUntilTime) {
      const lockedUntilTime = user.lockedUntilTime
      const locked = lockedUntilTime && subTime(now(), lockedUntilTime) < 0
      if (locked) {
        result.status = s.locked
        return result
      }
    } else if (
      user.failTime &&
      user.failTime instanceof Date &&
      this.lockedMinutes !== undefined &&
      user.failCount !== undefined &&
      this.maxPasswordFailed !== undefined &&
      user.failCount >= this.maxPasswordFailed
    ) {
      const lockedUntilTime = addMinutes(user.failTime, this.lockedMinutes)
      const locked = lockedUntilTime && subTime(now(), lockedUntilTime) < 0
      if (locked) {
        result.status = s.locked
        return result
      }
    }

    let passwordExpiredTime = null
    if (user.passwordModifiedTime && user.maxPasswordAge && user.maxPasswordAge > 0) {
      passwordExpiredTime = addDays(user.passwordModifiedTime, user.maxPasswordAge)
    }
    if (passwordExpiredTime && subTime(now(), passwordExpiredTime) > 0) {
      result.status = s.password_expired
      return result
    }
    if (!isValidAccessDate(user.accessDateFrom, user.accessDateTo)) {
      result.status = s.disabled
      return result
    }
    if (!isValidAccessTime(user.accessTimeFrom, user.accessTimeTo)) {
      result.status = s.access_time_locked
      return result
    }
    const contact = user.contact ? user.contact : user.email
    if (contact && this.hash && this.expires && this.expires > 0 && this.codeRepository && this.send && this.compare) {
      let twoFactors = user.twoFactors
      if (!twoFactors && this.hasTwoFactors) {
        twoFactors = await this.hasTwoFactors(user.id)
      }
      if (twoFactors) {
        if (!info.step || info.step <= 1) {
          const sentCode = this.generate()
          const savedCode = await this.hash(sentCode)
          const codeExpired = addSeconds(new Date(), this.expires)
          const res0 = await this.codeRepository.save(user.id, savedCode, codeExpired)
          if (res0 > 0) {
            await this.send(contact, sentCode, codeExpired, info.username)
            return { status: this.status.two_factor_required }
          } else {
            return { status: this.status.fail }
          }
        } else {
          if (!info.passcode || info.passcode.length === 0) {
            return { status: this.status.fail }
          }
          const code = await this.codeRepository.load(user.id)
          if (!code) {
            return { status: this.status.fail }
          }
          if (code.expiredAt.getTime() < tnow.getTime()) {
            return { status: this.status.fail }
          }
          const validPasscode = await this.compare(info.passcode, code.code)
          if (!validPasscode) {
            return { status: this.status.fail }
          } else {
            await this.codeRepository.delete(user.id)
          }
        }
      }
    }
    if (user.deactivated) {
      result.status = s.success_and_reactivated
    } else {
      result.status = s.success
    }
    const account = mapAll<UserInfo<ID>, Account>(user, this.account)

    if (this.getPrivileges) {
      const privileges = await this.getPrivileges(user.id)
      account.privileges = privileges
    }
    result.user = account
    if (this.repository.pass) {
      return this.repository.pass(user.id, user.deactivated).then((isStatus) => {
        if (!isStatus) {
          result.status = s.fail
        }
        return result
      })
    } else {
      return result
    }
  }
}
export const LoginService = Authenticator
export const SigninService = Authenticator
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
export function setTokenExpiredTime<ID>(user: UserInfo<ID>, expires: number): CustomToken {
  if (!user.accessTimeTo || !user.accessTimeFrom || !user.accessDateFrom || !user.accessDateTo) {
    const x = addSeconds(now(), expires / 1000)
    return { expiredTime: x, expires }
  }

  if (before(user.accessTimeTo, user.accessTimeFrom) || equalDate(user.accessTimeTo, user.accessDateFrom)) {
    const tmp = addHours(user.accessTimeTo, 24)
    user.accessDateTo = tmp
  }

  let tokenExpiredTime: Date = new Date()
  let jwtExpiredTime = 0

  if (expires > Math.abs(subTime(user.accessTimeTo, now()))) {
    tokenExpiredTime = addSeconds(now(), subTime(user.accessTimeTo, now()))
    jwtExpiredTime = Math.abs(subTime(user.accessTimeTo, now())) / 1000
  } else {
    tokenExpiredTime = addSeconds(now(), expires / 1000)
    jwtExpiredTime = expires
  }
  return { expiredTime: tokenExpiredTime, expires: jwtExpiredTime }
}

export function isValidAccessDate(fromDate?: Date, toDate?: Date): boolean {
  const today = now()
  if (fromDate && toDate) {
    const toDateNew = addHours(toDate, 24)
    if (before(fromDate, today) || (equalDate(fromDate, today) && before(toDate, toDateNew))) {
      return true
    }
  } else if (toDate) {
    const toDateNew = addHours(toDate, 24)
    if (before(today, toDateNew)) {
      return true
    }
  } else if (fromDate) {
    if (before(fromDate, today) || equalDate(fromDate, today)) {
      return true
    }
  } else {
    return true
  }
  return false
}
export function isValidAccessTime(fromTime?: Date, toTime?: Date): boolean {
  const today = now()
  if (fromTime && toTime) {
    if (before(toTime, fromTime) || equalDate(toTime, fromTime)) {
      toTime = addHours(toTime, 24)
    }
    if (before(fromTime, today) || (equalDate(fromTime, today) && before(today, toTime)) || equalDate(toTime, today)) {
      return true
    }
  } else if (toTime) {
    if (before(today, toTime) || equalDate(toTime, today)) {
      return true
    }
    return false
  } else if (fromTime) {
    if (before(fromTime, today) || equalDate(fromTime, today)) {
      return true
    }
    return false
  }
  return true
}

export function addSeconds(date: Date, number: number): Date {
  const d = new Date(date)
  d.setSeconds(d.getSeconds() + number)
  return d
}
export function addMinutes(date: Date, number: number): Date {
  const d = new Date(date)
  d.setMinutes(d.getMinutes() + number)
  return d
}
export function addHours(date: Date, number: number): Date {
  const d = new Date(date)
  d.setHours(d.getHours() + number)
  return d
}
export function addDays(date: Date, number: number): Date {
  const d = new Date(date)
  d.setDate(d.getDate() + number)
  return d
}
/*
export function after(date1?: Date, date2?: Date): boolean {
  if (!date1 || !date2) {
    return false;
  }
  if (date1.getTime() - date2.getTime() > 0) {
    return true;
  }
  return false;
}
*/
export function before(d1?: Date, d2?: Date): boolean {
  if (!d1 || !d2) {
    return false
  }
  if (d1.getTime() - d2.getTime() < 0) {
    return true
  }
  return false
}
export function now(): Date {
  return new Date()
}
// return milliseconds
export function subTime(d1: Date, d2: Date): number {
  if (d1 && d2) {
    const n1 = d1.getTime()
    const n2 = d2.getTime()
    const x = n1 - n2
    return x
  }
  if (d1) {
    return 1
  }
  if (d2) {
    return -1
  }
  return 0
}
export function equalDate(d1?: Date, d2?: Date): boolean {
  if (!d1 || !d2) {
    return true
  }
  if (d1.getTime() - d2.getTime() === 0) {
    return true
  }
  return false
}
// tslint:disable-next-line:max-classes-per-file
export class PrivilegesLoader {
  constructor(public query: <T>(sql: string, args?: any[]) => Promise<T[]>, public sql: string, public count?: number) {
    this.privileges = this.privileges.bind(this)
  }
  privileges(userId: string): Promise<Privilege[]> {
    const p = [userId]
    if (this.count && this.count >= 2) {
      for (let i = 2; i <= this.count; i++) {
        p.push(userId)
      }
    }
    return this.query<Module>(this.sql, [userId]).then((v) => {
      if (v && v.length >= 2) {
        if (v[0].permissions !== undefined) {
          return toPrivileges(orPermissions(v))
        }
      }
      return toPrivileges(v)
    })
  }
}
export const PrivilegeService = PrivilegesLoader
export const PrivilegeRepository = PrivilegesLoader
// tslint:disable-next-line:max-classes-per-file
export class PrivilegesReader {
  constructor(public query: <T>(sql: string, args?: any[]) => Promise<T[]>, public sql: string) {
    this.privileges = this.privileges.bind(this)
  }
  privileges(): Promise<Privilege[]> {
    return this.query<Module>(this.sql).then((v) => toPrivileges(v))
  }
}
export function toPrivileges(m: Module[]): Privilege[] {
  const ps: Module[] = getRoot(m)
  for (const p of ps) {
    getChildren(p, m)
  }
  return ps.sort(subPrivilege)
}
export function getRoot(ms: Module[]): Module[] {
  const ps: Module[] = []
  for (const m of ms) {
    if (!m.parent || m.parent.length === 0) {
      delete m.parent
      ps.push(m)
    }
  }
  return ps.sort(subPrivilege)
}
export function getChildren(m: Module, all: Module[]) {
  const children: Privilege[] = []
  for (const s of all) {
    if (s.parent === m.id) {
      delete s.parent
      children.push(s)
      getChildren(s, all)
    }
  }
  if (children.length > 0) {
    children.sort(subPrivilege)
    m.children = children
  }
}
export function orPermissions(all: Module[]): Module[] {
  if (all.length <= 1) {
    return all
  }
  const modules = all.sort(subPrivilegeId)
  const ms: Module[] = []
  const l = all.length
  const l1 = l - 1
  for (let i = 0; i < l1; ) {
    for (let j = i + 1; j < l; j++) {
      if (modules[i].id === modules[j].id) {
        // tslint:disable-next-line:no-bitwise
        modules[i].permissions = modules[i].permissions | modules[j].permissions
        if (j === l1) {
          ms.push(modules[i])
          i = l1 + 3
          break
        }
      } else {
        ms.push(modules[i])
        i = j
      }
    }
  }
  if (l >= 2) {
    if (modules[l1].id !== modules[l1 - 1].id) {
      ms.push(modules[l1])
    }
  }
  return ms
}
export function subPrivilegeId(p1: Privilege, p2: Privilege): number {
  return subString(p1.id, p2.id)
}
export function subPrivilege(p1: Privilege, p2: Privilege): number {
  return sub(p1.sequence, p2.sequence)
}
export function subString(n1?: string, n2?: string): number {
  if (!n1 && !n2) {
    return 0
  } else if (n1 && n2) {
    return n1.localeCompare(n2)
  } else if (n1) {
    return 1
  } else if (n2) {
    return -1
  }
  return 0
}
export function sub(n1?: number, n2?: number): number {
  if (!n1 && !n2) {
    return 0
  } else if (n1 && n2) {
    return n1 - n2
  } else if (n1) {
    return n1
  } else if (n2) {
    return -n2
  }
  return 0
}
// use to map payload for JWT
export function map<T>(obj: T, m?: StringMap): any {
  if (!m) {
    return obj
  }
  const mkeys = Object.keys(m)
  if (mkeys.length === 0) {
    return obj
  }
  const obj2: any = {}
  const keys = Object.keys(m as any)
  for (const key of keys) {
    let k0 = m[key]
    if (!k0) {
      k0 = key
    }
    const v = (obj as any)[key]
    if (v !== undefined) {
      obj2[k0] = v
    }
  }
  return obj2
}
export const deletedFields = [
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
]
export function mapAll<T, R>(obj: T, m?: StringMap): R {
  if (!m) {
    return obj as any
  }
  const mkeys = Object.keys(m)
  if (mkeys.length === 0) {
    return obj as any
  }
  const obj2: any = {}
  const keys = Object.keys(obj as any)
  for (const key of keys) {
    let k0 = m[key]
    if (!k0) {
      k0 = key
    }
    obj2[k0] = (obj as any)[key]
  }
  for (const f of deletedFields) {
    delete obj2[f]
  }
  return obj2
}
export function initializeStatus(s?: StatusConf): Status {
  const timeout: number | string = s && s.timeout ? s.timeout : -1
  const fail: number | string = s && s.fail ? s.fail : 0
  const success: number | string = s && s.success ? s.success : 1
  const success_and_reactivated: number | string = s && s.success_and_reactivated ? s.success_and_reactivated : 1
  const password_expired: number | string = s && s.password_expired ? s.password_expired : fail
  const two_factor_required: number | string = s && s.two_factor_required ? s.two_factor_required : 2
  const wrong_password: number | string = s && s.wrong_password ? s.wrong_password : fail
  const locked: number | string = s && s.locked ? s.locked : fail
  const suspended: number | string = s && s.suspended ? s.suspended : fail
  const disabled: number | string = s && s.disabled ? s.disabled : fail
  const access_time_locked: number | string = s && s.access_time_locked ? s.access_time_locked : fail
  const error: number | string = s && s.error ? s.error : fail
  return {
    timeout,
    fail,
    success,
    success_and_reactivated,
    password_expired,
    two_factor_required,
    wrong_password,
    locked,
    suspended,
    disabled,
    access_time_locked,
    error,
  }
}
export const fields = [
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
]
export function createMap(): StringMap {
  const m: StringMap = {}
  for (const s of fields) {
    m[s.toLowerCase()] = s
  }
  return m
}
export function getUser<ID>(obj: UserInfo<ID>, status?: string, s?: UserStatus, maxPasswordAge?: number): UserInfo<ID> {
  if (status && status.length > 0) {
    const t = (obj as any)[status]
    if (t !== undefined && t != null && s) {
      if (s.deactivated !== undefined && t === s.deactivated) {
        obj.deactivated = true
      }
      if (s.suspended !== undefined && t === s.suspended) {
        obj.suspended = true
      }
      if (s.disable !== undefined && t === s.disable) {
        obj.disable = true
      }
    }
    delete (obj as any)[status]
  }
  if (maxPasswordAge !== undefined && maxPasswordAge > 0 && (!obj.maxPasswordAge || obj.maxPasswordAge < 0)) {
    obj.maxPasswordAge = maxPasswordAge
  }
  return obj
}
export function useUserRepository<ID, C extends SqlAuthConfig>(db: DB, c: C, m?: StringMap): SqlUserRepository<ID> {
  const n = m ? m : createMap()
  return new SqlUserRepository(db, c.db, c.query, c.userStatus, n)
}
export const createUserRepository = useUserRepository
export const createUserService = useUserRepository
export const useUserService = useUserRepository
// tslint:disable-next-line:max-classes-per-file
export class SqlUserRepository<ID> implements UserRepository<ID> {
  constructor(public db: DB, public conf: DBConfig, public query: string, public status?: UserStatus, mp?: StringMap) {
    this.map = mp
    this.id = !this.conf.id || this.conf.id.length === 0 ? "id" : this.conf.id
    this.password = conf.password ? conf.password : conf.user
    this.getUser = this.getUser.bind(this)
    this.pass = this.pass.bind(this)
    this.fail = this.fail.bind(this)
  }
  id: string
  password: string
  fields: any
  map?: StringMap
  getUser(username: string): Promise<UserInfo<ID> | null | undefined> {
    const c = this.conf
    return this.db.query<UserInfo<ID>>(this.query, [username], this.map).then((v) => {
      return !v || v.length <= 0 ? undefined : getUser(v[0], c.status, this.status, c.maxPasswordAge)
    })
  }
  pass(userId: ID, deactivated?: boolean): Promise<boolean> {
    const c = this.conf
    const pass: any = {}
    if (c.successTime.length > 0) {
      pass[c.successTime] = new Date()
    }
    if (c.failTime.length > 0) {
      pass[c.failTime] = null
    }
    if (c.failCount.length > 0) {
      pass[c.failCount] = 0
    }
    if (c.lockedUntilTime.length > 0) {
      pass[c.lockedUntilTime] = null
    }
    const keys = Object.keys(pass)
    const l = keys.length
    if (l === 0) {
      return Promise.resolve(true)
    }
    if (!deactivated || !this.status || c.status.length === 0) {
      const stmt = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId)
      return this.db.exec(stmt.query, stmt.params).then((v) => (v > 0 ? true : false))
    } else {
      const activated = this.status.activated
      if (activated && activated !== "") {
        if (c.user === c.password || c.password === undefined) {
          pass[c.status] = activated
          const stmt = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId)
          return this.db.exec(stmt.query, stmt.params).then((v) => (v > 0 ? true : false))
        } else {
          const stmt1 = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId)
          const query = `update ${c.user} set ${c.status} = ${this.db.param(1)} where ${this.id} = ${this.db.param(2)}`
          const params: any[] = [activated, userId]
          const stmt2: Statement = { query, params }
          return this.db.execBatch([stmt1, stmt2], true).then((v) => (v > 0 ? true : false))
        }
      } else {
        const stmt = buildUpdatePassword(pass, this.db.param, this.password, this.id, userId)
        return this.db.exec(stmt.query, stmt.params).then((v) => (v > 0 ? true : false))
      }
    }
  }
  fail(userId: ID, failCount?: number, lockedUntilTime?: Date | null): Promise<boolean> {
    const c = this.conf
    const pass: any = {}
    if (c.failTime.length > 0) {
      pass[c.failTime] = new Date()
    }
    if (c.failCount.length > 0 && failCount !== undefined) {
      pass[c.failCount] = failCount + 1
    }
    if (lockedUntilTime !== undefined && c.lockedUntilTime.length > 0) {
      pass[c.lockedUntilTime] = lockedUntilTime
    }
    const keys = Object.keys(pass)
    const l = keys.length
    if (keys.length === 0) {
      return Promise.resolve(true)
    }
    const stmt = buildUpdate(pass, this.db.param)
    const query = `update ${this.password} set ${stmt.query} where ${this.id} = ${this.db.param(l + 1)}`
    const params: any[] = []
    if (stmt.params && stmt.params.length > 0) {
      for (const pr of stmt.params) {
        params.push(pr)
      }
    }
    params.push(userId)
    return this.db.exec(query, params).then((v) => (v > 0 ? true : false))
  }
}
export function buildUpdatePassword<ID, T>(pass: T, buildParam: (i: number) => string, table: string, idName: string, id: ID): Statement {
  const stmt = buildUpdate(pass, buildParam)
  const k = stmt.params ? stmt.params.length + 1 : 1
  const query = `update ${table} set ${stmt.query} where ${idName} = ${buildParam(k)}`
  const params: any[] = []
  if (stmt.params && stmt.params.length > 0) {
    for (const pr of stmt.params) {
      params.push(pr)
    }
  }
  params.push(id)
  stmt.query = query
  stmt.params = params
  return stmt
}
export function buildUpdate<T>(obj: T, buildParam: (i: number) => string): Statement {
  const keys = Object.keys(obj as any)
  const cols: string[] = []
  const params: any[] = []
  const o: any = obj
  let i = 1
  for (const key of keys) {
    const v = o[key]
    if (v != null) {
      cols.push(`${key} = ${buildParam(i++)}`)
      params.push(v)
    } else if (v == null) {
      cols.push(`${key} = null`)
    }
  }
  const query = cols.join(",")
  return { query, params }
}
export const SqlUserService = SqlUserRepository
export function generate(length?: number): string {
  if (!length) {
    length = 6
  }
  return padLeft(Math.floor(Math.random() * Math.floor(Math.pow(10, length) - 1)).toString(), length, "0")
}
export function padLeft(str: string, length: number, pad: string) {
  if (str.length >= length) {
    return str
  }
  let str2 = str
  while (str2.length < length) {
    str2 = pad + str2
  }
  return str2
}
export type EmailData = string | { name?: string; email: string }
export interface MailContent {
  type: string
  value: string
}
export interface MailData {
  to?: EmailData | EmailData[]

  from: EmailData
  replyTo?: EmailData

  subject?: string
  html?: string
  content?: MailContent[]
}
// tslint:disable-next-line:max-classes-per-file
export class MailSender {
  constructor(public sendMail: (mailData: MailData) => Promise<boolean>, public from: EmailData, public body: string, public subject: string) {
    this.send = this.send.bind(this)
  }
  send(to: string, passcode: string, expireAt: Date): Promise<boolean> {
    const diff = Math.abs(Math.round((Date.now() - expireAt.getTime()) / 1000 / 60))
    const body = util.format(this.body, ...[passcode, diff])
    const msg = {
      to,
      from: this.from,
      subject: this.subject,
      html: body,
    }
    return this.sendMail(msg)
  }
}
export const CodeMailSender = MailSender
