package it.cnr.si;

import it.cnr.si.service.AceService;
import it.cnr.si.service.dto.anagrafica.scritture.BossDto;
import it.cnr.si.service.dto.anagrafica.simpleweb.SimpleRuoloWebDto;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;
import org.jboss.logging.Logger;
import org.keycloak.representations.IDToken;

import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AceOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, FullNameMapper.class);
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
            if(username.toUpperCase().startsWith("TINIT")) {

                try {
                    String codiceFiscale = username.substring(6).toUpperCase();
                    String ldapUsername = aceService.getUtenteByCodiceFiscale(codiceFiscale).getUsername();
                    username = ldapUsername;
                } catch (Exception e) {
                    LOGGER.info("utente " + username + " spid non presente in ldap");
                }
            }

            LOGGER.info(username);

            // ruoli
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

            // eo
            final String user = username;
            for(String contesto: contesti) {
                Map<String, List> rolesWithEo = simpleRuoloWebDtos
                        .stream()
                        .filter(r -> r.getContesto().getSigla().equals(contesto))
                        .map(r -> r.getSigla())
                        .filter(r -> !getEoRolesFromContext(user, contesto, r).isEmpty())
                        .collect(Collectors.toMap(r -> r, r -> getEoRolesFromContext(user, contesto, r)));

                if(!rolesWithEo.isEmpty()) {
                    ((Map) contexts.get(contesto)).put("entitaOrganizzative", rolesWithEo);
                }
            }


        } catch (Exception e) {
            LOGGER.error(e);
        }

        token.getOtherClaims().put("contexts", contexts);
        token.getOtherClaims().put("preferred_username", username);
        token.getOtherClaims().put("username_cnr", username);

    }

    private List getEoRolesFromContext(String username, String context, String role) {
        return aceService.ruoliEoAttivi(username).stream()
                .filter(r -> r.getRuolo().getContesto().getSigla().equals(context))
                .filter(r -> r.getRuolo().getSigla().equals(role))
                .filter(r -> Optional.ofNullable(r.getEntitaOrganizzativa()).isPresent())
                .map(BossDto::getEntitaOrganizzativa)
                .map(r -> new HashMap(){{
                    put("id", r.getId());
                    put("idnsip", r.getIdnsip());
                    put("sigla", r.getSigla());
                }})
                .collect(Collectors.toList());
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
