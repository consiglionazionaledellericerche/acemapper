package it.cnr.si;

import it.cnr.si.service.AceService;
import it.cnr.si.service.dto.anagrafica.UserInfoDto;
import it.cnr.si.service.dto.anagrafica.scritture.BossDto;
import it.cnr.si.service.dto.anagrafica.simpleweb.SimpleRuoloWebDto;
import it.cnr.si.service.dto.anagrafica.simpleweb.SsoModelWebDto;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;
import org.jboss.logging.Logger;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.stream.Collectors;

public class AceOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String ACE_CONTEXT_CONFIG = "ace.contexts";
    public static final String ROLES_EO = "rolesEo";

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ACE_CONTEXT_CONFIG);
        property.setLabel("Ace Contexts");
        property.setHelpText("Insert Ace Contexts Value (comma separated value)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "oidc-customprotocolmapper";
    public static final String DISPLAY_NAME = "ace mapper";
    public static final String HELP_TEXT = "role and context mapper";

    private static final Logger LOGGER = Logger.getLogger(AceOIDCProtocolMapper.class);

    private AceService aceService = new AceService();

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_NAME;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        Map contexts = new HashMap();
        // ldap o spid username
        String username = userSession.getUser().getUsername();
        try {
            // nel caso di username spid
            if(isSpidUsername(username)) {
                try {
                    String codiceFiscale = username.substring(6).toUpperCase();
                    String ldapUsername = aceService.getUtenteByCodiceFiscale(codiceFiscale).getUsername();
                    username = ldapUsername;
                } catch (Exception e) {
                    LOGGER.info("utente " + username + " spid non presente in ldap");
                }
            }
            LOGGER.info(username);

            Optional<String> aceContexts = Optional.ofNullable(mappingModel.getConfig().get(ACE_CONTEXT_CONFIG));
            LOGGER.info("ACE Mapper configurato con il contesto di ACE: " + aceContexts);

            final String user = username;
            final List<SsoModelWebDto> roles = new ArrayList<SsoModelWebDto>();
            if (!aceContexts.isPresent()) {
                roles.addAll(aceService.ruoliSsoAttivi(user));
            } else {
                roles.addAll(aceService.ruoliSsoAttivi(user, aceContexts.get()));
            }
            final Map<String, List<String>> contestiRuoli = roles
                    .stream()
                    .filter(ssoModelWebDto -> Optional.ofNullable(ssoModelWebDto.getSiglaContesto()).isPresent())
                    .collect(Collectors.groupingBy(SsoModelWebDto::getSiglaContesto, Collectors.mapping(SsoModelWebDto::getSiglaRuolo, Collectors.toList())));

            contestiRuoli.entrySet()
                    .stream()
                    .forEach(stringListEntry -> {
                        Map<String, List<String>> mappa = new HashMap<>();
                        mappa.put("roles", stringListEntry.getValue());
                        contexts.put(stringListEntry.getKey(), mappa);

                        // Ruoli assegnti su una specifica Entità organizzativa
                        final List<SsoModelWebDto> rolesWithEo =
                                roles
                                        .stream()
                                        .filter(ssoModelWebDto -> ssoModelWebDto.getSiglaContesto().equals(stringListEntry.getKey()))
                                        .filter(ssoModelWebDto -> !ssoModelWebDto.getEntitaOrganizzative().isEmpty())
                                        .collect(Collectors.toList());
                        if (!rolesWithEo.isEmpty()) {
                            ((Map)contexts.get(stringListEntry.getKey())).put(ROLES_EO, rolesWithEo);
                        }
                    });
        } catch (Exception e) {
            LOGGER.error(e);
        }

        token.getOtherClaims().put("contexts", contexts);
        token.getOtherClaims().put("preferred_username", username);
        token.getOtherClaims().put("username_cnr", username);

    }

    private boolean isSpidUsername(String username) {
        return username.toUpperCase().startsWith("TINIT");
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        if (idToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        if (userInfo) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
        mapper.setConfig(config);
        return mapper;
    }

}
