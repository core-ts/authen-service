export interface StringMap {
  [key: string]: string;
}
export interface UserRepository {
  getUser(userId: string): Promise<UserInfo|null|undefined>;
  pass?(userId: string, deactivated?: boolean): Promise<boolean>;
  fail?(userId: string, failCount?: number, lockedUntilTime?: Date): Promise<boolean>;
}
export interface Token {
  secret: string;
  expires: number;
}
export interface UserInfo {
  id: string;
  username: string;
  email?: string;
  displayName: string;
  gender?: string;
  password?: string;
  disable?: boolean;
  deactivated?: boolean;
  suspended?: boolean;
  // lockedUntilTime?: Date;
  successTime?: Date;
  failTime?: Date;
  failCount?: number;
  passwordModifiedTime?: Date;
  maxPasswordAge?: number;
  roles?: string[];

  userType?: string;
  privileges?: string[];
  accessDateFrom?: Date;
  accessDateTo?: Date;
  accessTimeFrom?: Date;
  accessTimeTo?: Date;

  language?: string;
  dateFormat?: string;
  timeFormat?: string;
  imageURL?: string;
}
export interface UserStatus {
  activated?: number | string;
  deactivated?: number | string;
  disable?: number | string;
  suspended?: number | string;
}
export interface StatusConf {
  timeout?: number | string;
  fail?: number | string;
  success?: number | string;
  success_and_reactivated?: number | string;
  password_expired?: number | string;
  two_factor_required?: number | string;
  wrong_password?: number | string;
  locked?: number | string;
  suspended?: number | string;
  disabled?: number | string;
  access_time_locked?: number | string;
  error?: number | string;
}
export interface Status {
  timeout: number | string;
  fail: number | string;
  success: number | string;
  success_and_reactivated: number | string;
  password_expired: number | string;
  two_factor_required: number | string;
  wrong_password: number | string;
  locked: number | string;
  suspended: number | string;
  disabled: number | string;
  access_time_locked: number | string;
  error: number | string;
}
export interface ErrorMessage {
  field: string;
  code: string;
  param?: string | number | Date;
  message?: string;
}
export interface AuthInfo {
  step?: number;
  username: string;
  password: string;
  passcode?: string;
  ip?: string;
  device?: string;
}
export interface AuthResult {
  status: number | string;
  user?: UserAccount;
  message?: string;
}
export interface UserAccount {
  id?: string;
  username?: string;
  contact?: string;
  email?: string;
  phone?: string;
  displayName?: string;
  passwordExpiredTime?: Date;
  token?: string;
  tokenExpiredTime?: Date;
  newUser?: boolean;
  userType?: string;
  roles?: string[];
  privileges?: Privilege[];
  language?: string;
  dateFormat?: string;
  timeFormat?: string;
  gender?: string;
  imageURL?: string;
}
export interface Privilege {
  id?: string;
  name: string;
  resource?: string;
  path?: string;
  icon?: string;
  sequence?: number;
  children?: Privilege[];
  permissions?: number;
}
export interface Module {
  id?: string;
  name: string;
  resource?: string;
  path?: string;
  icon?: string;
  sequence?: number;
  parent?: string;
  children?: Privilege[];
  permissions: number;
}
/*
export interface StoredUser {
  userId?: string;
  username?: string;
  contact?: string;
  // displayName: string;
  // gender?: Gender;
  // passwordExpiredTime?: Date;
  // token?: string;
  // tokenExpiredDate?: Date;
  // newUser?: boolean;
  userType?: string;
  roles?: string[];
  privileges?: string[];
  tokens?: any;
  // privileges?: Privilege[];
}*/
export interface CustomJwtToken {
  tokenExpiredTime: Date;
  jwtTokenExpires: number;
}
export interface Statement {
  query: string;
  params?: any[];
}
export interface DB {
  exec(sql: string, args?: any[], ctx?: any): Promise<number>;
  execBatch(statements: Statement[], firstSuccess?: boolean, ctx?: any): Promise<number>;
  query<T>(sql: string, args?: any[], m?: StringMap): Promise<T[]>;
}
export interface BaseConfig {
  status?: UserStatus;
  statusName?: string;
  maxPasswordAge?: number;
  time?: boolean;
}
export interface SqlConfig extends BaseConfig {
  sql: {
    query: string;
    fail?: string;
    pass?: string;
    pass2?: string;
  };
}
export interface AuthConfig extends BaseConfig {
  status?: StatusConf;
}
export interface RepoConfig extends SqlConfig {
  status?: StatusConf;
}
