# KipuBankV2

KipuBankV2 es una versión mejorada y más cercana a producción del contrato KipuBank original.

Para esta versión, se pidio añadir:
  1. Control de acceso, utilizando contratos de OpenZeppelin
  2. Soporte multi-token (ETH + ERC-20)
  3. Contabilidad interna por token
  4. Normalización de decimales a unidades USDC (6 decimales)
  5. Uso de oráculos Chainlink para convertir valores a USD y control del límite global en USD
  6. Mejores prácticas de seguridad y eficiencia

## Resumen de mejoras implementadas

1. **Control de Acceso (AccessControl de OpenZeppelin)**
   - Implementación: se usan 'DEFAULT_ADMIN_ROLE' y 'ADMIN_ROLE'. El constructor recibe una cuenta 'admin' y se le otorgan roles.
   - Funciones administrativas ('registerToken', 'unregisterToken', 'addAdmin', 'removeAdmin') restringidas a 'ADMIN_ROLE' o 'DEFAULT_ADMIN_ROLE' según corresponda.

2. **Soporte Multi-token (ETH + ERC-20)**
   - Uso: 'address(0)' representa ETH. Para ERC-20 hay funciones 'depositERC20' y 'withdraw(token, amount)'.
   - Se mantiene contabilidad por token: 'balances[user][token]' y 'totalDepositedByToken[token]'.

3. **Contabilidad Interna Multi-token**
   - Mappings anidados: 'mapping(address => mapping(address => uint256)) balances;'
   - 'totalDepositedByToken' guarda totales por token.
   - 'totalDepositedUSDC' lleva la suma convertida a USDC (6 decimales) de los tokens registrados con price feed.

4. **Eventos y Errores Personalizados**
   - Errores personalizados: 'LimiteBancoExcedidoUSD', 'SaldoInsuficiente', 'RetiroExcedeLimite', 'MontoCero', 'TransferenciaFallida', 'TokenNoSoportado', 'SoloAdmin', 'DecimalesInvalidos'
   - Eventos: 'Deposit', 'Withdraw', 'TokenRegistered', 'TokenUnregistered', 'AdminAdded', 'AdminRemoved'.

5. **Oráculos de Datos (Chainlink)**
   - Para que un token cuente dentro del límite global, el admin debe registrar el token y su price feed con 'registerToken(token, priceFeed, decimals)'.
   - El contrato usa el price feed (asumimos feeds con 8 decimales, típico de Chainlink) para convertir cantidades nativas a USD y normalizarlas a USDC (6 decimales).
   - ETH se modela como 'token = address(0)' y requiere su price feed registrado si se desea que cuente para el límite.

6. **Conversión de Decimales y Valores**
   - Se introdujo 'TokenInfo' con 'decimals' y 'priceFeed'.
   - Función '_convertTokenAmountToUSDC(token, amount)' normaliza distintas precisiones a USDC (6 decimales), usando la fórmula:
     - amountUSDC = (amount * price) / (10**tokenDecimals) / (10**(feedDecimals - USDC_DECIMALS))
   - 'USDC_DECIMALS' es una constant (6).

7. **Seguridad y Eficiencia**
   - Uso de 'ReentrancyGuard' y del patrón checks-effects-interactions.
   - Uso de constant y immutable (USDC_DECIMALS, limiteBancoUSDC, limiteRetiroWei).
   - Errores personalizados en lugar de strings en 'require' para ahorro de gas.
   - Manejo de transferencias ETH con call y chequeo de retorno, y transfer de ERC-20 mediante 'IERC20.transfer'.
   - Funciones administrativas protegidas con roles.

---

## Decisiones de diseño importantes / trade-offs

1. **Límite del banco en USD (USDC)**
   - En lugar de mantener el límite global en ETH (como en la versión original), definimos 'limiteBancoUSDC' (unidad: USDC, 6 decimales). Esto facilita comparar valores de múltiples activos.
   - **Trade-off**: para que un token contribuya al límite global, el administrador **debe** registrar el token y proporcionar un price feed (esto evita suposiciones incorrectas de precio, pero requiere gestión por parte del admin).

2. **Registro explícito de tokens**
   - Se requiere que el admin registre tokens (y su feed) para incluirlos en la contabilidad global y conversiones. Depósitos de tokens no registrados se permiten (es decir, la bóveda puede custodiar tokens no registrados), pero **no** contarán dentro del límite global hasta que el admin los registre. Esto evita registrar feeds falsos o feeds inexistentes.
   - **Trade-off**: cierta carga operativa para el admin (debe registrar tokens), a cambio de seguridad y control preciso de precios.

3. **Simplicidad vs. Complejidad de precios**
   - El contrato asume que los feeds de Chainlink devuelven 8 decimales (caso común). Si en tu red existen feeds con diferentes 'feedDecimals', habría que extender la implementación para leer 'decimals()' del feed (Chainlink no provee una interfaz estándar con 'decimals()' en todos los casos) o almacenar 'feedDecimals' al registrar el token.
   - **Recomendación**: registrar feeds oficiales y consistentes por red (p. ej. Mainnet, Goerli, etc.).

4. **Precisión y redondeos**
   - Se realizan divisiones enteras; habrá truncamiento en ciertas conversiones. Para la mayoría de aplicaciones esto es aceptable, pero si se necesita máxima precisión financiera, se tendrían que usar librerías de punto fijo o mayores multiplicadores.

5. **Retiro de ERC-20**
   - No se impone un límite por retiro uniforme para todos los tokens. Para ETH hay un 'limiteRetiroWei' inmutable. Si se quiere un limite por token se podria extender 'TokenInfo' con un 'maxWithdrawal' por token.

6. **Seguridad**
   - Se aplicó 'nonReentrant' y checks-effects-interactions.
---

## Instrucciones de despliegue e interacción

### Requisitos
- Dependencias: OpenZeppelin (AccessControl, ReentrancyGuard, IERC20), Chainlink contracts.
- Version de Solidity: `0.8.26`.
