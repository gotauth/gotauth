// Type-level check of the typed client against the backend's OpenAPI document.
// `pnpm typecheck` first regenerates ./generated/openapi.ts from ../openapi.json
// (written by scripts/export_openapi.py), so a field added, removed or retyped on
// either side of a listed model fails `tsc`. Nothing here runs. Not covered: GET query
// inputs (OpenAPI parameters, not schemas) and outputs the server does not declare
// (ChallengeOut, and the union answers of the two-factor and passkey verify routes).
import type { components } from "./generated/openapi"
import type {
  AccountListOut,
  AccountOut,
  ApiKeyListOut,
  ApiKeyOut,
  BackupCodesOut,
  CreationOptionsOut,
  EnableOut,
  FullOrganizationOut,
  GotAuthClient,
  HasPermissionOut,
  InvitationListOut,
  InvitationOut,
  IssueApiKeyOut,
  MemberOut,
  OAuthConsentOut,
  OAuthGrantListOut,
  OAuthGrantOut,
  OAuthGrantRevokedOut,
  OrganizationListOut,
  OrganizationOut,
  OrganizationWithRoleOut,
  PasskeyListOut,
  PasskeyOut,
  RedirectOut,
  RequestOptionsOut,
  Session,
  SessionListOut,
  SessionWithUserOut,
  SetActiveOut,
  SignInOut,
  StatusOut,
  User,
} from "@/lib/gotauth-client"

type S = components["schemas"]

/** A and B accept the same values. */
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
/** The declared fields only: a model that allows extra fields has an index signature. */
type Known<T> = T extends object ? { [K in keyof T as string extends K ? never : K]: T[K] } : T
/** The client and the server agree on the values and on the field names. */
type Agree<A, B> =
  Same<Known<A>, Known<B>> extends true ? Same<keyof Known<A>, keyof Known<B>> : false
type Expect<T extends true> = T

type Body<F> = F extends (...args: infer A) => unknown
  ? NonNullable<A[A["length"] extends 2 ? 1 : 0]>
  : never

type C = GotAuthClient

export type ResponseChecks = [
  Expect<Agree<StatusOut, S["StatusOut"]>>,
  Expect<Agree<RedirectOut, S["RedirectOut"]>>,
  Expect<Agree<User, S["User"]>>,
  Expect<Agree<Session, S["Session"]>>,
  Expect<Agree<SessionWithUserOut, S["SessionWithUserOut"]>>,
  Expect<Agree<SignInOut, S["SignInOut"]>>,
  Expect<Agree<SessionListOut, S["SessionListOut"]>>,
  Expect<Agree<AccountOut, S["AccountOut"]>>,
  Expect<Agree<AccountListOut, S["AccountListOut"]>>,
  Expect<Agree<ApiKeyOut, S["ApiKeyOut"]>>,
  Expect<Agree<IssueApiKeyOut, S["IssueApiKeyOut"]>>,
  Expect<Agree<ApiKeyListOut, S["ApiKeyListOut"]>>,
  Expect<Agree<EnableOut, S["EnableOut"]>>,
  Expect<Agree<BackupCodesOut, S["BackupCodesOut"]>>,
  Expect<Agree<CreationOptionsOut, S["CreationOptionsOut"]>>,
  Expect<Agree<RequestOptionsOut, S["RequestOptionsOut"]>>,
  Expect<Agree<PasskeyOut, S["PasskeyOut"]>>,
  Expect<Agree<PasskeyListOut, S["PasskeyListOut"]>>,
  Expect<Agree<OrganizationOut, S["OrganizationOut"]>>,
  Expect<Agree<OrganizationWithRoleOut, S["OrganizationWithRoleOut"]>>,
  Expect<Agree<OrganizationListOut, S["OrganizationListOut"]>>,
  Expect<Agree<MemberOut, S["MemberOut"]>>,
  Expect<Agree<FullOrganizationOut, S["FullOrganizationOut"]>>,
  Expect<Agree<InvitationOut, S["InvitationOut"]>>,
  Expect<Agree<InvitationListOut, S["InvitationListOut"]>>,
  Expect<Agree<SetActiveOut, S["SetActiveOut"]>>,
  Expect<Agree<HasPermissionOut, S["HasPermissionOut"]>>,
  Expect<Agree<OAuthGrantOut, S["OAuthGrantOut"]>>,
  Expect<Agree<OAuthGrantListOut, S["OAuthGrantListOut"]>>,
  Expect<Agree<OAuthGrantRevokedOut, S["gotauth__contracts__http_models__RevokedOut"]>>,
  Expect<Agree<OAuthConsentOut, S["OAuthConsentOut"]>>,
]

export type RequestChecks = [
  Expect<Agree<Body<C["signUpEmail"]>, S["SignUpEmailIn"]>>,
  Expect<Agree<Body<C["signInEmail"]>, S["SignInEmailIn"]>>,
  Expect<Agree<Body<C["changePassword"]>, S["ChangePasswordIn"]>>,
  Expect<Agree<Body<C["resetPassword"]>, S["ResetPasswordIn"]>>,
  Expect<Agree<Body<C["revokeSession"]>, S["RevokeSessionIn"]>>,
  Expect<Agree<Body<C["unlinkAccount"]>, S["UnlinkAccountIn"]>>,
  Expect<Agree<Body<C["linkSocial"]>, S["LinkSocialIn"]>>,
  Expect<Agree<Body<C["signInSocial"]>, S["SignInSocialIn"]>>,
  Expect<Agree<Body<C["sendVerificationEmail"]>, S["SendVerificationEmailIn"]>>,
  Expect<Agree<Body<C["requestPasswordReset"]>, S["RequestPasswordResetIn"]>>,
  Expect<Agree<Body<C["changeEmail"]>, S["ChangeEmailIn"]>>,
  Expect<Agree<Body<C["updateUser"]>, S["UpdateUserIn"]>>,
  Expect<Agree<Body<C["deleteUser"]>, S["DeleteUserIn"]>>,
  Expect<Agree<Body<C["apiKeys"]["createApiKey"]>, S["CreateApiKeyIn"]>>,
  Expect<Agree<Body<C["apiKeys"]["updateApiKey"]>, S["UpdateApiKeyIn"]>>,
  Expect<Agree<Body<C["twoFactor"]["enableTwoFactor"]>, S["PasswordIn"]>>,
  Expect<Agree<Body<C["twoFactor"]["disableTwoFactor"]>, S["PasswordIn"]>>,
  Expect<Agree<Body<C["twoFactor"]["verifyTotp"]>, S["CodeIn"]>>,
  Expect<Agree<Body<C["twoFactor"]["verifyBackupCode"]>, S["CodeIn"]>>,
  Expect<Agree<Body<C["twoFactor"]["verifyTwoFactorOtp"]>, S["CodeIn"]>>,
  Expect<Agree<Body<C["passkey"]["verifyPasskeyRegistration"]>, S["RegisterIn"]>>,
  Expect<Agree<Body<C["passkey"]["signInPasskey"]>, S["SignInIn"]>>,
  Expect<Agree<Body<C["passkey"]["renamePasskey"]>, S["RenameIn"]>>,
  Expect<Agree<Body<C["magicLink"]["sendMagicLink"]>, S["SendMagicLinkIn"]>>,
  Expect<Agree<Body<C["emailOtp"]["sendEmailOtp"]>, S["SendEmailOtpIn"]>>,
  Expect<Agree<Body<C["emailOtp"]["verifyEmailOtp"]>, S["VerifyEmailOtpIn"]>>,
  Expect<Agree<Body<C["organization"]["createOrganization"]>, S["CreateOrganizationIn"]>>,
  Expect<Agree<Body<C["organization"]["updateOrganization"]>, S["UpdateOrganizationIn"]>>,
  Expect<Agree<Body<C["organization"]["deleteOrganization"]>, S["OrganizationIdIn"]>>,
  Expect<Agree<Body<C["organization"]["setActiveOrganization"]>, S["SetActiveIn"]>>,
  Expect<Agree<Body<C["organization"]["inviteMember"]>, S["InviteMemberIn"]>>,
  Expect<Agree<Body<C["organization"]["acceptInvitation"]>, S["AcceptInvitationIn"]>>,
  Expect<Agree<Body<C["organization"]["rejectInvitation"]>, S["AcceptInvitationIn"]>>,
  Expect<Agree<Body<C["organization"]["cancelInvitation"]>, S["InvitationIdIn"]>>,
  Expect<Agree<Body<C["organization"]["removeMember"]>, S["RemoveMemberIn"]>>,
  Expect<Agree<Body<C["organization"]["updateMemberRole"]>, S["UpdateMemberRoleIn"]>>,
  Expect<Agree<Body<C["organization"]["leaveOrganization"]>, S["OrganizationIdIn"]>>,
  Expect<Agree<Body<C["organization"]["hasPermission"]>, S["HasPermissionIn"]>>,
  Expect<Agree<Body<C["oauth2"]["revokeOauthGrant"]>, S["ClientIdIn"]>>,
]
