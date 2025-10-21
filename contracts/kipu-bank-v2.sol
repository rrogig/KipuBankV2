// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title KipuBankV2 — bóvedas personales multi-token con control en USD y oráculos Chainlink
/// @author
/// @notice Versión "cercana a producción" de KipuBank con: AccessControl, ReentrancyGuard,
///         soporte ETH + ERC-20, oráculos Chainlink, normalización de decimales, eventos y errores personalizados.
/// @dev Basado en patrones checks-effects-interactions y buenas prácticas de OpenZeppelin.
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract KipuBankV2 is AccessControl, ReentrancyGuard {
    /*/////////////////////////////////////////////////////////////
                              ERRORES
    /////////////////////////////////////////////////////////////*/

    error LimiteBancoExcedidoUSD(uint256 intentadoUSD, uint256 disponibleUSD);
    error SaldoInsuficiente(address usuario, address token, uint256 disponible, uint256 solicitado);
    error RetiroExcedeLimite(uint256 solicitado, uint256 limite);
    error MontoCero();
    error TransferenciaFallida(address destino, uint256 monto);
    error TokenNoSoportado(address token);
    error SoloAdmin();
    error DecimalesInvalidos();

    /*/////////////////////////////////////////////////////////////
                         ROLES - CONTROL DE ACCESO
    /////////////////////////////////////////////////////////////*/

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /*/////////////////////////////////////////////////////////////
                         DECLARACIONES DE TIPOS
    /////////////////////////////////////////////////////////////*/

    struct TokenInfo {
        bool supported;               // si el token fue registrado por admin
        address priceFeed;            // address del AggregatorV3Interface (token/USD)
        uint8 decimals;               // decimales del token (p.ej. USDC = 6, DAI = 18)
    }

    /*/////////////////////////////////////////////////////////////
                      CONSTANTES E INMUTABLES (Eficiencia)
    /////////////////////////////////////////////////////////////*/

    /// @notice Decimales objetivo interno: USDC (6)
    uint8 public constant USDC_DECIMALS = 6;

    /// @notice Factor para normalizaciones (1e6)
    uint256 private constant USDC_BASE = 10 ** uint256(USDC_DECIMALS);

    /// @notice Límite global en USD (unidad: USDC decimals), inmutable
    uint256 public immutable limiteBancoUSDC;

    /// @notice Límite por retiro en wei (ETH) para retiros de ETH; para ERC20 se aplica por token en unidades token-native
    uint256 public immutable limiteRetiroWei;

    /*/////////////////////////////////////////////////////////////
                           ESTADO
    /////////////////////////////////////////////////////////////*/

    /// @notice Saldos por usuario por token: balances[user][token] => amount (token-native units; ETH => token = address(0) and units = wei)
    mapping(address => mapping(address => uint256)) private balances;

    /// @notice Token metadata para conversiones y controles
    mapping(address => TokenInfo) public tokenInfo;

    /// @notice Total depositado por token (token-native units)
    mapping(address => uint256) public totalDepositedByToken;

    /// @notice Total depositado en USD (unidad: USDC decimals) calculado con price feeds; usado para comparar con limiteBancoUSDC
    uint256 public totalDepositedUSDC;

    /// @notice Contadores simples
    uint256 public depositCount;
    uint256 public withdrawCount;

    /*/////////////////////////////////////////////////////////////
                               EVENTOS
    /////////////////////////////////////////////////////////////*/

    event Deposit(address indexed user, address indexed token, uint256 amount, uint256 amountUSDC);
    event Withdraw(address indexed user, address indexed token, uint256 amount, uint256 amountUSDC);
    event TokenRegistered(address indexed token, address priceFeed, uint8 decimals);
    event TokenUnregistered(address indexed token);
    event AdminAdded(address indexed account);
    event AdminRemoved(address indexed account);

    /*/////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    /////////////////////////////////////////////////////////////*/

    /// @param _limiteBancoUSDC Límite global del banco, en unidades USDC (6 decimales). Ej: para $1,000, pasar 1_000 * 1e6
    /// @param _limiteRetiroWei Límite por retiro para ETH (wei). Retiros ERC20 están limitados por saldo y lógica del token.
    /// @param admin Admin inicial
    constructor(uint256 _limiteBancoUSDC, uint256 _limiteRetiroWei, address admin) {
        if (admin == address(0)) revert SoloAdmin();
        limiteBancoUSDC = _limiteBancoUSDC;
        limiteRetiroWei = _limiteRetiroWei;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        emit AdminAdded(admin);
    }

    /*/////////////////////////////////////////////////////////////
                             MODIFICADORES
    /////////////////////////////////////////////////////////////*/

    modifier montoNoCero(uint256 valor) {
        if (valor == 0) revert MontoCero();
        _;
    }

    modifier tokenSoportadoOETH(address token) {
        // address(0) -> ETH (siempre permitido)
        if (token != address(0) && !tokenInfo[token].supported) revert TokenNoSoportado(token);
        _;
    }

    /*/////////////////////////////////////////////////////////////
                    FUNCIONES DE ADMINISTRACION (CONTROL DE ACCESO)
    /////////////////////////////////////////////////////////////*/

    /// @notice Registra un token y su price feed (token/USD) para incluirlo en el límite global
    /// @dev ADMIN_ROLE required
    function registerToken(address token, address priceFeed, uint8 decimals) external onlyRole(ADMIN_ROLE) {
        if (decimals == 0) revert DecimalesInvalidos();
        tokenInfo[token] = TokenInfo({
            supported: true,
            priceFeed: priceFeed,
            decimals: decimals
        });
        emit TokenRegistered(token, priceFeed, decimals);
    }

    /// @notice Elimina soporte (desregistra) un token
    function unregisterToken(address token) external onlyRole(ADMIN_ROLE) {
        delete tokenInfo[token];
        emit TokenUnregistered(token);
    }

    /// @notice Añade un nuevo ADMIN
    function addAdmin(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(ADMIN_ROLE, account);
        emit AdminAdded(account);
    }

    /// @notice Elimina un ADMIN
    function removeAdmin(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(ADMIN_ROLE, account);
        emit AdminRemoved(account);
    }

    /*/////////////////////////////////////////////////////////////
                             FUNCIONES PÚBLICAS
    /////////////////////////////////////////////////////////////*/

    /// @notice Deposita ETH enviando msg.value (token = address(0))
    function depositETH() external payable montoNoCero(msg.value) nonReentrant {
        _deposit(address(0), msg.sender, msg.value);
    }

    /// @notice Deposita un token ERC-20 previamente aprobado al contrato
    /// @param token Dirección del token ERC-20 (no usar address(0) para ERC20)
    /// @param amount Cantidad en unidades del token (según sus decimales)
    function depositERC20(address token, uint256 amount) external montoNoCero(amount) nonReentrant {
        if (token == address(0)) revert TokenNoSoportado(token);
        // Transfer in
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        _deposit(token, msg.sender, amount);
    }

    /// @notice Retira fondos (ETH si token == address(0), sino ERC20)
    /// @param token token address (address(0) -> ETH)
    /// @param amount cantidad a retirar (wei para ETH, token-units para ERC20)
    function withdraw(address token, uint256 amount) external montoNoCero(amount) nonReentrant tokenSoportadoOETH(token) {
        uint256 userBalance = balances[msg.sender][token];
        if (amount > userBalance) revert SaldoInsuficiente(msg.sender, token, userBalance, amount);

        // Para ETH aplicamos un límite por retiro (en wei)
        if (token == address(0) && amount > limiteRetiroWei) revert RetiroExcedeLimite(amount, limiteRetiroWei);

        // Computamos el equivalente en USD para decrementar el total SI el token esta registrado únicamente
        uint256 amountUSDC = 0;
        if (token == address(0)) {
            // ETH
            if (tokenInfo[address(0)].supported || tokenInfo[address(0)].priceFeed != address(0)) {
                amountUSDC = _convertTokenAmountToUSDC(address(0), amount);
                // Effects on totalDepositedUSDC below
            }
        } else {
            if (tokenInfo[token].supported) {
                amountUSDC = _convertTokenAmountToUSDC(token, amount);
            }
        }

        // Effects (update state before interaction)
        balances[msg.sender][token] = userBalance - amount;
        totalDepositedByToken[token] -= amount;
        if (amountUSDC > 0) {
            // Esta operacion es segura porque chequeamos los balances previamente
            totalDepositedUSDC = totalDepositedUSDC > amountUSDC ? totalDepositedUSDC - amountUSDC : 0;
        }
        unchecked { withdrawCount++; }

        // Interactions
        if (token == address(0)) {
            (bool ok, ) = msg.sender.call{value: amount}("");
            if (!ok) revert TransferenciaFallida(msg.sender, amount);
        } else {
            bool sent = IERC20(token).transfer(msg.sender, amount);
            if (!sent) revert TransferenciaFallida(msg.sender, amount);
        }

        emit Withdraw(msg.sender, token, amount, amountUSDC);
    }

    /// @notice Consulta saldo de un usuario para un token específico
    function balanceOf(address user, address token) external view returns (uint256) {
        return balances[user][token];
    }

    /// @notice Devuelve el total depositado (token-native units) por token
    function totalDepositedForToken(address token) external view returns (uint256) {
        return totalDepositedByToken[token];
    }

    /// @notice Consulta el límite global del banco en USDC (6 decimales)
    function getLimiteBancoUSDC() external view returns (uint256) {
        return limiteBancoUSDC;
    }

    /// @notice Devuelve el total depositado en el banco en USDC (6 decimales)
    function getTotalDepositedUSDC() external view returns (uint256) {
        return totalDepositedUSDC;
    }

    /*/////////////////////////////////////////////////////////////
                           FUNCIONES INTERNAS
    /////////////////////////////////////////////////////////////*/

    /// @dev Lógica general de depósito (ETH o ERC20)
    function _deposit(address token, address usuario, uint256 amount) private tokenSoportadoOETH(token) {
        // Calcular equivalente en USD (si existe price feed)
        uint256 amountUSDC = 0;
        bool contributesToCap = false;

        if (token == address(0)) {
            if (tokenInfo[address(0)].supported || tokenInfo[address(0)].priceFeed != address(0)) {
                amountUSDC = _convertTokenAmountToUSDC(address(0), amount);
                contributesToCap = true;
            }
        } else {
            if (tokenInfo[token].supported) {
                amountUSDC = _convertTokenAmountToUSDC(token, amount);
                contributesToCap = true;
            }
        }

        // Checks: si contribuye al cap global en USD, verificar límite
        if (contributesToCap) {
            uint256 nuevoTotalUSDC = totalDepositedUSDC + amountUSDC;
            if (nuevoTotalUSDC > limiteBancoUSDC) {
                revert LimiteBancoExcedidoUSD(nuevoTotalUSDC, limiteBancoUSDC - totalDepositedUSDC);
            }
            totalDepositedUSDC = nuevoTotalUSDC;
        }

        // Effects
        balances[usuario][token] += amount;
        totalDepositedByToken[token] += amount;
        unchecked { depositCount++; }

        emit Deposit(usuario, token, amount, amountUSDC);
    }

    /// @dev Convierte una cantidad de token (o ETH si token==address(0)) a USDC-equivalente (6 decimales)
    /// @param token dirección del token (address(0) para ETH)
    /// @param amount cantidad en unidades nativas (wei para ETH)
    /// @return amountUSDC equivalente en unidades USDC (6 decimals)
    function _convertTokenAmountToUSDC(address token, uint256 amount) internal view returns (uint256) {
        address feedAddr;
        uint8 tokenDecimals;

        if (token == address(0)) {
            // ETH: esperamos que admin haya registrado priceFeed para address(0)
            TokenInfo memory info = tokenInfo[address(0)];
            feedAddr = info.priceFeed;
            tokenDecimals = 18; // ETH tiene 18 decimales
            if (feedAddr == address(0)) revert TokenNoSoportado(token);
        } else {
            TokenInfo memory info = tokenInfo[token];
            if (!info.supported || info.priceFeed == address(0)) revert TokenNoSoportado(token);
            feedAddr = info.priceFeed;
            tokenDecimals = info.decimals;
        }

        AggregatorV3Interface priceFeed = AggregatorV3Interface(feedAddr);
        (, int256 priceInt, , , ) = priceFeed.latestRoundData();
        require(priceInt > 0, "Price feed invalid");
        uint256 price = uint256(priceInt); // price with feed-decimals (commonly 8)

        // Los precios de Chainlink normalmente tienen 8 decimales (1e8). Asumo feedDecimals = 8
        // Para convertir a USDC (6 decimales) => dividir por 10**(feedDecimals - USDC_DECIMALS)

        // Si feedDecimals == 8 and USDC_DECIMALS == 6, dividir por 1e2.

        uint8 feedDecimals = 8;
        // Paso 1: cantidad * precio
        uint256 numerator = amount * price;

        // Paso 2: dividir por la cantidad de deciales del token, para obtener USD con decimales del feed
        uint256 usdWithFeedDecimals = numerator / (10 ** tokenDecimals);

        // Paso 3: normalizar feedDecimals a USDC decimals
        
        if (feedDecimals >= USDC_DECIMALS) {
            uint256 factor = 10 ** uint256(feedDecimals - USDC_DECIMALS);
            return usdWithFeedDecimals / factor;
        } else {
            // improbable, but handle case where feedDecimals < USDC_DECIMALS
            uint256 factor = 10 ** uint256(USDC_DECIMALS - feedDecimals);
            return usdWithFeedDecimals * factor;
        }
    }

    /*/////////////////////////////////////////////////////////////
                           FUNCIONES HELPER / INFO
    /////////////////////////////////////////////////////////////*/

    /// @notice Devuelve el price feed address registrado para un token (o address(0) si none)
    function getPriceFeedForToken(address token) external view returns (address) {
        return tokenInfo[token].priceFeed;
    }

    /// @notice Devuelve si un token está registrado para participar en el límite global
    function isTokenRegistered(address token) external view returns (bool) {
        return tokenInfo[token].supported;
    }

    /// @notice Intento de lectura segura de decimals desde el token (no usado directamente; usamos registerToken.decimals)
    function tryTokenDecimals(address token) external view returns (uint8) {
        try IERC20Metadata(token).decimals() returns (uint8 d) {
            return d;
        } catch {
            return 18; // fallback razonable
        }
    }

    /*/////////////////////////////////////////////////////////////
                           RECEPCIÓN DE ETH
    /////////////////////////////////////////////////////////////*/

    /// @notice receive ETH -> se comporta como depositETH; requiere que admin haya registrado price feed para ETH si se desea que cuente para el cap
    receive() external payable {
        if (msg.value == 0) revert MontoCero();
        _deposit(address(0), msg.sender, msg.value);
    }

    fallback() external payable {
        revert();
    }
}
