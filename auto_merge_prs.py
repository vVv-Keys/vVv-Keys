#!/usr/bin/env python3
"""
🚀 Bulk Auto-Merge for vVv-Keys Dependency PRs
Enables auto-merge on all safe Snyk dependency update PRs
Excludes: TAPEROOM-ARCHIVES.com, VocalLab-TapeArchives.com
"""

import subprocess
import sys
import time
from typing import Dict, List, Tuple

class PRAutoMerger:
    def __init__(self):
        self.prs_to_merge: Dict[str, List[int]] = {
            "vVv-Keys/Keys-Ventures": [57, 56, 55, 54, 53, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 37, 36, 35, 34, 33, 29, 28, 27, 26, 25, 20, 19, 18, 17, 16],
            "vVv-Keys/GHOSTFRAME": [52, 51, 50, 49, 48, 47, 46],
            "vVv-Keys/404-CTI-Dashboard": [37, 36, 35, 34, 33],
            "vVv-Keys/404-KeysTools": [47, 42, 41, 40, 39, 38, 37, 33],
            "vVv-Keys/404-GHOSTSEC-BLUE": [43, 42, 41, 40, 39],
            "vVv-Keys/404-backup": [6, 5, 4, 3, 2],
            "vVv-Keys/404-VETTED-DISCORD-DASHBOARD": [7, 6, 5, 4, 3],
        }
        self.completed = 0
        self.failed: List[Tuple[str, str]] = []
        self.total = sum(len(prs) for prs in self.prs_to_merge.values())

    def merge_pr(self, repo: str, pr_num: int) -> bool:
        """Attempt to enable auto-merge for a PR"""
        try:
            # Try squash merge (preferred for clean history)
            result = subprocess.run(
                ["gh", "pr", "merge", f"{repo}#{pr_num}", "--squash", "--auto"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                return True
            
            # Fallback to regular merge commit
            result = subprocess.run(
                ["gh", "pr", "merge", f"{repo}#{pr_num}", "--merge", "--auto"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            self.failed.append((f"{repo}#{pr_num}", "Timeout"))
            return False
        except Exception as e:
            self.failed.append((f"{repo}#{pr_num}", str(e)))
            return False

    def run(self):
        """Execute bulk auto-merge"""
        print("\n" + "="*70)
        print("🚀 BULK AUTO-MERGE PROCESSOR")
        print("="*70)
        print(f"📊 Total PRs to process: {self.total}")
        print(f"📦 Repositories: {len(self.prs_to_merge)}")
        print("="*70 + "\n")
        
        for repo, pr_numbers in self.prs_to_merge.items():
            print(f"\n📦 {repo}")
            print(f"   Processing {len(pr_numbers)} PRs...")
            print("   " + "-"*60)
            
            for i, pr_num in enumerate(pr_numbers, 1):
                status = "⏳"
                
                if self.merge_pr(repo, pr_num):
                    status = "✅"
                    self.completed += 1
                else:
                    status = "❌"
                
                percent = (i / len(pr_numbers)) * 100
                print(f"   {status} PR #{pr_num:3d} [{i:2d}/{len(pr_numbers):2d}] ({percent:5.1f}%)")
                time.sleep(0.3)  # Rate limiting
        
        self.print_summary()

    def print_summary(self):
        """Print final summary"""
        print("\n" + "="*70)
        print("✨ AUTO-MERGE SETUP COMPLETE!")
        print("="*70)
        print(f"✅ Successful:  {self.completed}/{self.total} ({(self.completed/self.total)*100:.1f}%)")
        print(f"⏳ Status:      Queued for automatic merge when CI passes")
        
        if self.failed:
            print(f"\n⚠️  Failed:     {len(self.failed)} PRs need manual review")
            print("\nFailed PRs:")
            for pr, reason in self.failed:
                print(f"  • {pr:40s} ({reason})")
        else:
            print(f"\n🎉 All {self.total} PRs queued successfully!")
        
        print("="*70 + "\n")

def main():
    """Main entry point"""
    try:
        # Verify gh CLI is installed
        result = subprocess.run(
            ["gh", "--version"],
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            print("❌ GitHub CLI (gh) is not installed or not in PATH")
            print("   Install from: https://cli.github.com/")
            sys.exit(1)
        
        # Run the merger
        merger = PRAutoMerger()
        merger.run()
        
        # Exit with appropriate code
        sys.exit(0 if len(merger.failed) == 0 else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
