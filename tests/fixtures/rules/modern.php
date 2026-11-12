<?php
declare(strict_types=1);
namespace App;
final class Svc {
    public function __construct(private ?Repo $repo = null) {}
    public function run(array $ids): int {
        $stmt = $this->pdo->prepare('SELECT * FROM t WHERE id = ?');
        $stmt->execute([$ids[0]]);
        return count($ids ?? []);
    }
}
