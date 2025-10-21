// SPDX-License-Identifier: MIT
// File: @openzeppelin/contracts/access/IAccessControl.sol


// OpenZeppelin Contracts (last updated v5.4.0) (access/IAccessControl.sol)

pragma solidity >=0.8.4;

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

// File: @openzeppelin/contracts/utils/Context.sol


// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// File: @openzeppelin/contracts/utils/introspection/IERC165.sol


// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/IERC165.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// File: @openzeppelin/contracts/utils/introspection/ERC165.sol


// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/ERC165.sol)

pragma solidity ^0.8.20;


/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// File: @openzeppelin/contracts/access/AccessControl.sol


// OpenZeppelin Contracts (last updated v5.4.0) (access/AccessControl.sol)

pragma solidity ^0.8.20;




/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` from `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

// File: @openzeppelin/contracts/security/ReentrancyGuard.sol


// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}

// File: @openzeppelin/contracts/token/ERC20/IERC20.sol


// OpenZeppelin Contracts (last updated v5.4.0) (token/ERC20/IERC20.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// File: @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol


// OpenZeppelin Contracts (last updated v5.4.0) (token/ERC20/extensions/IERC20Metadata.sol)

pragma solidity >=0.6.2;


/**
 * @dev Interface for the optional metadata functions from the ERC-20 standard.
 */
interface IERC20Metadata is IERC20 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}

// File: @chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol


pragma solidity ^0.8.0;

interface AggregatorV3Interface {
  function decimals() external view returns (uint8);

  function description() external view returns (string memory);

  function version() external view returns (uint256);

  function getRoundData(
    uint80 _roundId
  ) external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

  function latestRoundData()
    external
    view
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

// File: contracts/kipu-bank-v2.sol


pragma solidity 0.8.26;

/// @title KipuBankV2 — bóvedas personales multi-token con control en USD y oráculos Chainlink
/// @author
/// @notice Versión "cercana a producción" de KipuBank con: AccessControl, ReentrancyGuard,
///         soporte ETH + ERC-20, oráculos Chainlink, normalización de decimales, eventos y errores personalizados.
/// @dev Basado en patrones checks-effects-interactions y buenas prácticas de OpenZeppelin.






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
