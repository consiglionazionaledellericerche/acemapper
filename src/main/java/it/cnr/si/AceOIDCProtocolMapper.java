package it.cnr.si;

import it.cnr.si.service.AceService;
import it.cnr.si.service.dto.anagrafica.simpleweb.SimpleRuoloWebDto;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

import java.util.*;
import org.jboss.logging.Logger;
import java.util.stream.Collectors;

public class AceOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "oidc-customprotocolmapper";
    public static final String DISPLAY_NAME = "ace mapper";
    public static final String HELP_TEXT = "role and context mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList();

    private static final Logger LOGGER = Logger.getLogger(AceOIDCProtocolMapper.class);

    private AceService aceService = new AceService();

    @Override
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

    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        Map<String, Map<String, Set<String>>> contexts = new HashMap<>();

        try {
            String username = userSession.getUser().getUsername();
            LOGGER.info(username);
            List<SimpleRuoloWebDto> simpleRuoloWebDtos = aceService.ruoliAttivi(username);

            List<String> contesti = simpleRuoloWebDtos.stream()
                    .map(r -> r.getContesto().getSigla())
                    .collect(Collectors.toList());

            for(String contesto: contesti) {
                Set<String> ruoli = simpleRuoloWebDtos.stream()
                        .filter(a -> a.getContesto().getSigla().equals(contesto))
                        .map(a -> a.getSigla())
                        .collect(Collectors.toSet());

                Map<String, Set<String>> mappa = new HashMap<>();
                mappa.put("roles", ruoli);
                contexts.put(contesto, mappa);
            }

        } catch (Exception e) {
            LOGGER.error(e);
        }
        token.getOtherClaims().put("contexts", contexts);

        setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        return token;
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        mapper.setConfig(config);
        return mapper;
    }

}
