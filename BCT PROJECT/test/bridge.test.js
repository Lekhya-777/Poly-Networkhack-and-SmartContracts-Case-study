import pkg from "hardhat";
const { ethers } = pkg;
import { expect } from "chai";

describe("Bridge Vulnerability Case Study", function () {
  it("VulnerableBridge: forged raw signature allows withdraw", async function () {
    const signers = await ethers.getSigners();
    const funder = signers[0];
    const attacker = signers[1];

    // create owner wallet and fund it
    const ownerWallet = ethers.Wallet.createRandom().connect(ethers.provider);
    await funder.sendTransaction({ to: ownerWallet.address, value: ethers.parseEther("1") });

    // deploy vulnerable bridge
    const VB = await ethers.getContractFactory("VulnerableBridge");
    const vulnerable = await VB.connect(ownerWallet).deploy(ownerWallet.address);
    await vulnerable.waitForDeployment();

    // fund bridge
    await funder.sendTransaction({ to: vulnerable.target, value: ethers.parseEther("10") });

    // build message hash and raw signature
    const amount = 10n;
    const messageHash = ethers.keccak256(ethers.solidityPacked(["address", "uint256"], [attacker.address, amount]));
    const sigObj = ownerWallet.signingKey.sign(messageHash);
    const rawSignature = ethers.Signature.from(sigObj).serialized;

    // attacker withdraws with raw signature -> should succeed (no revert)
    await expect(vulnerable.connect(attacker).withdraw(amount, rawSignature)).to.not.be.reverted;
  });

  it("PatchedBridge: same raw signature is rejected", async function () {
    const signers = await ethers.getSigners();
    const funder = signers[0];
    const attacker = signers[1];

    const ownerWallet = ethers.Wallet.createRandom().connect(ethers.provider);
    await funder.sendTransaction({ to: ownerWallet.address, value: ethers.parseEther("1") });

    const PB = await ethers.getContractFactory("PatchedBridge");
    const patched = await PB.connect(ownerWallet).deploy(ownerWallet.address);
    await patched.waitForDeployment();

    await funder.sendTransaction({ to: patched.target, value: ethers.parseEther("10") });

    const amount = 10n;
    const messageHash = ethers.keccak256(ethers.solidityPacked(["address", "uint256"], [attacker.address, amount]));
    const sigObj = ownerWallet.signingKey.sign(messageHash);
    const rawSignature = ethers.Signature.from(sigObj).serialized;

    // attacker withdraws with raw signature -> should revert with "unauthorized"
    await expect(patched.connect(attacker).withdraw(amount, rawSignature)).to.be.revertedWith("unauthorized");
  });

  it("Comparison: vulnerable succeeds and patched fails for same forged raw sig", async function () {
    const signers = await ethers.getSigners();
    const funder = signers[0];
    const attacker = signers[1];

    const ownerWallet = ethers.Wallet.createRandom().connect(ethers.provider);
    await funder.sendTransaction({ to: ownerWallet.address, value: ethers.parseEther("1") });

    const VB = await ethers.getContractFactory("VulnerableBridge");
    const vulnerable = await VB.connect(ownerWallet).deploy(ownerWallet.address);
    await vulnerable.waitForDeployment();
    await funder.sendTransaction({ to: vulnerable.target, value: ethers.parseEther("10") });

    const PB = await ethers.getContractFactory("PatchedBridge");
    const patched = await PB.connect(ownerWallet).deploy(ownerWallet.address);
    await patched.waitForDeployment();
    await funder.sendTransaction({ to: patched.target, value: ethers.parseEther("10") });

    const amount = 10n;
    const messageHash = ethers.keccak256(ethers.solidityPacked(["address", "uint256"], [attacker.address, amount]));
    const sigObj = ownerWallet.signingKey.sign(messageHash);
    const rawSignature = ethers.Signature.from(sigObj).serialized;

    await expect(vulnerable.connect(attacker).withdraw(amount, rawSignature)).to.not.be.reverted;
    await expect(patched.connect(attacker).withdraw(amount, rawSignature)).to.be.revertedWith("unauthorized");
  });
});
