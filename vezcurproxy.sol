//_ SPDX-License-Identifier: UNLICENSED

//_ Copyright (C) Vylte-finuka

pragma solidity ^0.8.18;

import "./@openzeppelin/contracts-upgradeable@4.8.2/token/ERC20/ERC20Upgradeable.sol";
import "./@openzeppelin/contracts-upgradeable@4.8.2/access/OwnableUpgradeable.sol";
import "./@openzeppelin/contracts-upgradeable@4.8.2/proxy/utils/Initializable.sol";
import "./@openzeppelin/contracts-upgradeable@4.8.2/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";
import "./@openzeppelin/contracts/utils/Base64.sol";
import "./EACAggregatorProxy.sol";
import "./@openzeppelin/contracts/proxy/Proxy.sol";
import "./@openzeppelin/contracts/access/Ownable.sol";
import "./@openzeppelin/contracts/proxy/ERC1967/ERC1967Upgrade.sol";
import "./@openzeppelin/contracts-upgradeable@4.8.2/proxy/utils/UUPSUpgradeable.sol";

    //_ ========================= Others Functions ==================================
contract ERC1967Proxy is Proxy, ERC1967Upgrade {
    //_
    //_ @dev Initializes the upgradeable proxy with an initial implementation specified by `_logic`.
    //_
    //_ If `_data` is nonempty, it's used as data in a delegate call to `_logic`. This will typically be an encoded
    //_ function call, and allows initializing the storage of the proxy like a Solidity constructor.
    //_
    constructor(address _logic, bytes memory _data) payable {
        assert(_IMPLEMENTATION_SLOT == bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1));
        _upgradeToAndCall(_logic, _data, false);
    }

    //_
    //_ @dev Returns the current implementation address.
    //_
    function _implementation() internal view virtual override returns (address impl) {
        return ERC1967Upgrade._getImplementation();
    }
}

contract Proxiable {
    // Code position in storage is keccak256("PROXIABLE") = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

    function updateCodeAddress(address newAddress) internal {
        require(
            bytes32(0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7) == Proxiable(newAddress).proxiableUUID(),
            "Not compatible"
        );
        assembly { // solium-disable-line
            sstore(0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7, newAddress)
        }
    }
    function proxiableUUID() public pure returns (bytes32) {
        return 0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7;
    }
}

    //_ ========================= Externals Functions ==================================
contract ProofOfReserve {
    address public owner;
    uint256 public totalValue;
    AggregatorV3Interface public priceFeed;

    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function setPriceFeed(address _priceFeed) public {
        require(msg.sender == owner, "Only owner can call this function");
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function proveReserve() public view returns (bool) {
        (,int256 price,,,) = priceFeed.latestRoundData();
        uint256 balance = address(this).balance;
        return (balance * uint256(price) == totalValue * 10**18);
    }

    function deposit() public payable {
        totalValue += msg.value;
    }

    function withdrawTo() public {
        require(msg.sender == owner, "Only owner can call this function");
        payable(msg.sender).transfer(address(this).balance);
    }
}

   //_ ============================= Constructor ===================================   
contract VEZproxy is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {
    EACAggregatorProxy public priceFeed;
    string public currency = "EUR";

    //_ @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        
    }

    function initialize() initializer public {
        __ERC20_init("Vyft Enhancing ZER", "VEZ");
        __Ownable_init();
        __UUPSUpgradeable_init();
    }
    //_ ============================ External Function ==============================
        function mintToLuzia(address recipient, uint256 amount) public onlyOwner {
        _mint(recipient, amount);
    }
    
    //_ ============================ Internal Function ==============================

    modifier onlyAllowedUser(address user) {
    require(msg.sender == user);
    _;
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        onlyOwner
        override
    {}
    mapping(address => uint256) public _balances;

    mapping(address => mapping(address => uint256)) public _allowances;

    uint256 public _initSupply;

    address public blacklister;
    mapping(address => bool) internal blacklisted;

    event Blacklisted(address indexed _account);
    event UnBlacklisted(address indexed _account);
    event BlacklisterChanged(address indexed newBlacklister);

    //_
    //_@dev Throws if called by any account other than the blacklister
    //_
    modifier onlyBlacklister() {
        require(
            msg.sender == blacklister,
            "Blacklistable: caller is not the blacklister"
        );
        _;
    }

    //_
    //_@dev Throws if argument account is blacklisted
    //_@param _account The address to check
    //_
    modifier notBlacklisted(address _account) {
        require(
            !blacklisted[_account],
            "Blacklistable: account is blacklisted"
        );
        _;
    }

    //_
    //_@dev Checks if account is blacklisted
    //_@param _account The address to check
    //_
    function isBlacklisted(address _account) external view returns (bool) {
        return blacklisted[_account];
    }

    //_
    //_@dev Adds account to blacklist
    //_@param _account The address to blacklist
    //_
    function blacklist(address _account) external payable {
        blacklisted[_account] = true;
        emit Blacklisted(_account);
    }

    //_
    //_@dev Removes account from blacklist
    //_@param _account The address to remove from the blacklist
    //_
    function unBlacklist(address _account) external payable {
        blacklisted[_account] = false;
        emit UnBlacklisted(_account);
    }

    function updateBlacklister(address _newBlacklister) external payable {
        require(
            _newBlacklister != address(0),
            "Blacklistable: new blacklister is the zero address"
        );
        blacklister = _newBlacklister;
        emit BlacklisterChanged(blacklister);
    }

    //_
    //_@dev Emitted when the pause is triggered by `account`.
    //_
    event Paused(address account);

    //_
    //_@dev Emitted when the pause is lifted by `account`.
    //_
    event Unpaused(address account);

    bool public _paused;

    //_
    //_@dev Modifier to make a function callable only when the contract is not paused.
    //_
    //_Requirements:
    //_
    //_- The contract must not be paused.
    //_
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    //_
    //_@dev Modifier to make a function callable only when the contract is paused.
    //_
    //_Requirements:
    //_
    //_- The contract must be paused.
    //_
    modifier whenPaused() {
        _requirePaused();
        _;
    }

    //_
    //_@dev Returns true if the contract is paused, and false otherwise.
    //_
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    //_
    //_@dev Throws if the contract is paused.
    //_
    function _requireNotPaused() internal view virtual {
        require(!paused(), "Pausable: paused");
    }

    //_
    //_@dev Throws if the contract is not paused.
    //_
    function _requirePaused() internal view virtual {
        require(paused(), "Pausable: not paused");
    }

    //_
    //_@dev Triggers stopped state.
    //_
    //_Requirements:
    //_
    //_- The contract must not be paused.
    //_
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    //_
    //_@dev Returns to normal state.
    //_
    //_Requirements:
    //_
    //_- The contract must be paused.
    //_
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }

    //_
    //_@dev See {IERC20-balanceOf}.
    //_
    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    //_
    //_@dev See {IERC20-transfer}.
    //_
    //_Requirements:
    //_
    //_- `to` cannot be the zero address.
    //_- the caller must have a balance of at least `amount`.
    //_
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, amount);
        return true;
    }

    //_
    //_@dev See {IERC20-allowance}.
    //_
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    //_
    //_@dev See {IERC20-approve}.
    //_
    //_NOTE: If `amount` is the maximum `uint256`, the allowance is not updated on
    //_`transferFrom`. This is semantically equivalent to an infinite approval.
    //_
    //_Requirements:
    //_
    //_- `spender` cannot be the zero address.
    //_
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, amount);
        return true;
    }

    //_
    //_@dev See {IERC20-transferFrom}.
    //_
    //_Emits an {Approval} event indicating the updated allowance. This is not
    //_required by the EIP. See the note at the beginning of {ERC20}.
    //_
    //_NOTE: Does not update the allowance if the current allowance
    //_is the maximum `uint256`.
    //_
    //_Requirements:
    //_
    //_- `from` and `to` cannot be the zero address.
    //_- `from` must have a balance of at least `amount`.
    //_- the caller must have allowance for ``from``'s tokens of at least
    //_`amount`.
    //_
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }

    //_
    //_@dev Atomically increases the allowance granted to `spender` by the caller.
    //_
    //_This is an alternative to {approve} that can be used as a mitigation for
    //_problems described in {IERC20-approve}.
    //_
    //_Emits an {Approval} event indicating the updated allowance.
    //_
    //_Requirements:
    //_
    //_- `spender` cannot be the zero address.
    //_
    function increaseAllowance(address spender, uint256 addedValue) public virtual override  returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, allowance(owner, spender) + addedValue);
        return true;
    }

    //_
    //_@dev Atomically decreases the allowance granted to `spender` by the caller.
    //_
    //_This is an alternative to {approve} that can be used as a mitigation for
    //_problems described in {IERC20-approve}.
    //_
    //_Emits an {Approval} event indicating the updated allowance.
    //_
    //_Requirements:
    //_
    //_- `spender` cannot be the zero address.
    //_- `spender` must have allowance for the caller of at least
    //_`subtractedValue`.
    //_
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override  returns (bool) {
        address owner = _msgSender();
        uint256 currentAllowance = allowance(owner, spender);
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(owner, spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    //_
    //_@dev Moves `amount` of tokens from `from` to `to`.
    //_
    //_This internal function is equivalent to {transfer}, and can be used to
    //_e.g. implement automatic token fees, slashing mechanisms, etc.
    //_
    //_Emits a {Transfer} event.
    //_
    //_Requirements:
    //_
    //_- `from` cannot be the zero address.
    //_- `to` cannot be the zero address.
    //_- `from` must have a balance of at least `amount`.
    //_
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual override {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(from, to, amount);

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
            // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by
            // decrementing then incrementing.
            _balances[to] += amount;
        }

        emit Transfer(from, to, amount);

        _afterTokenTransfer(from, to, amount);
    }

    //_ @dev Creates `amount` tokens and assigns them to `account`, increasing
    //_the total supply.
    //_
    //_Emits a {Transfer} event with `from` set to the zero address.
    //_
    //_Requirements:
    //_
    //_- `account` cannot be the zero address.
    //_
    function _mint(address account, uint256 amount) internal virtual override {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _initSupply += amount;
        unchecked {
            // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.
            _balances[account] += amount;
        }
        emit Transfer(address(0), account, amount);

        _afterTokenTransfer(address(0), account, amount);
    }

    //_
    //_@dev Destroys `amount` tokens from `account`, reducing the
    //_total supply.
    //_
    //_Emits a {Transfer} event with `to` set to the zero address.
    //_
    //_Requirements:
    //_
    //_- `account` cannot be the zero address.
    //_- `account` must have at least `amount` tokens.
    //_
    function _burn(address account, uint256 amount) internal virtual override {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        unchecked {
            _balances[account] = accountBalance - amount;
            // Overflow not possible: amount <= accountBalance <= totalSupply.
            _initSupply -= amount;
        }

        emit Transfer(account, address(0), amount);

        _afterTokenTransfer(account, address(0), amount);
    }

    //_
    //_@dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.
    //_
    //_This internal function is equivalent to `approve`, and can be used to
    //_e.g. set automatic allowances for certain subsystems, etc.
    //_
    //_Emits an {Approval} event.
    //_
    //_Requirements:
    //_
    //_- `owner` cannot be the zero address.
    //_- `spender` cannot be the zero address.
    //_
    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal virtual override {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

            function mint(address to, uint256 amount) public payable onlyOwner {
        _mint(to, amount);
    }

    //_
    //_@dev Updates `owner` s allowance for `spender` based on spent `amount`.
    //_
    //_Does not update the allowance amount in case of infinite allowance.
    //_Revert if not enough allowance is available.
    //_
    //_Might emit an {Approval} event.
    //_
    function _spendAllowance(
        address owner,
        address spender,
        uint256 amount
    ) internal virtual override  {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }
}