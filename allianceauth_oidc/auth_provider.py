"""Custom DOT OAuth2Validator that enforces Alliance Auth access policy."""

from django.core.exceptions import PermissionDenied
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import errors as oauth_errors

from .security import check_user_state_and_groups


class AllianceAuthOAuth2Validator(OAuth2Validator):
    """Wrap DOT's validator with state/group checks and AA-specific claims."""

    # Bind the AA-specific "groups" claim to the standard "profile" scope
    # so consumers don't need to request a separate scope to receive it.
    # (DOT's get_oidc_claims filters claims by oidc_claim_scope; any new
    # claim added to get_additional_claims must have a matching entry here
    # or it will silently never reach userinfo / id_token.)
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope.copy()
    oidc_claim_scope.update({"groups": "profile"})

    @staticmethod
    def _enforce_policy(request, client) -> bool:
        """
        Run the per-app state/groups gate against ``request.user``.

        Returns True if the policy allows the operation, False otherwise. Used
        as a post-validation hook by validate_code and validate_refresh_token
        so the same gate runs on every token-issuing path; missing it on either
        side leaves a hole.
        """
        try:
            user = getattr(request, "user", None)
            if user is not None and client is not None:
                check_user_state_and_groups(user, client)
        except PermissionDenied:
            return False
        return True

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Ensure app/user policy is enforced during authorization_code
        exchange (before a token is persisted).
        """
        if not super().validate_code(
            client_id, code, client, request, *args, **kwargs
        ):
            return False
        return self._enforce_policy(request, client)

    def validate_refresh_token(
        self, refresh_token, client, request, *args, **kwargs
    ):
        """Ensure app/user policy is enforced during refresh_token flow."""
        if not super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        ):
            return False
        return self._enforce_policy(request, client)

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Final guard: block persistence if policy fails.
        This prevents "token issued then denied" races/500s.
        """
        try:
            user = getattr(request, "user", None)
            client = getattr(request, "client", None) or getattr(
                request, "application", None
            )
            if user is not None and client is not None:
                check_user_state_and_groups(user, client)
        except PermissionDenied:
            # Convert to OAuth error response (no 500). `from None` suppresses
            # the PermissionDenied chain so the OAuth client only sees the
            # protocol-level error, not Django internals.
            raise oauth_errors.InvalidGrantError(
                description="Access denied"
            ) from None
        return super().save_bearer_token(token, request, *args, **kwargs)

    def get_additional_claims(self, request):
        """Augment DOT's id_token/userinfo claims with AA-specific values."""
        out = super().get_additional_claims(request)
        user = getattr(request, "user", None)
        if user is None:
            return out
        # email — Django sets a blank string when no email is registered;
        # only emit the claim when there's a real value. Strip whitespace
        # so accidental "  " entries (from copy-paste or buggy admin
        # imports) don't leak into the claim and break RFC 5321 contracts
        # downstream.
        email = getattr(user, "email", None)
        if isinstance(email, str):
            email = email.strip() or None
        if email:
            out["email"] = email
        groups = getattr(user, "groups", None)
        profile = getattr(user, "profile", None)
        main_character = getattr(profile, "main_character", None)
        # picture (avatar)
        character_id = getattr(main_character, "character_id", None)
        if character_id:
            out["picture"] = (
                f"https://images.evetech.net/characters/{character_id}/portrait?size=128"
            )
        # name
        character_name = getattr(main_character, "character_name", None)
        if character_name:
            out["name"] = character_name
        # groups + state. Sort the Django groups so the claim is
        # deterministic across calls (downstream consumers hash claim
        # payloads for caching). The state name is appended after sorting
        # so its position in the list is stable.
        state = getattr(profile, "state", None)
        state_name = getattr(state, "name", None)
        if groups is None:
            groups_list = []
        else:
            groups_list = sorted(groups.all().values_list("name", flat=True))
        if state_name is not None:
            groups_list.append(state_name)
        if groups_list:
            out["groups"] = groups_list
        # locale — UserProfile.language is a CharField with default="" when
        # the user hasn't picked a language. The bare `is not None` check
        # would leak the empty string as a claim.
        locale = getattr(profile, "language", None)
        if locale:
            out["locale"] = locale
        return out
