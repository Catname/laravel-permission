<?php

namespace Catname\Permission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;

interface Role
{
    /**
     * A role may be given various permissions.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function permissions(): BelongsToMany;

    /**
     * Find a role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Catname\Permission\Contracts\Role
     *
     * @throws \Catname\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByName(string $name, $guardName): self;

    /**
     * Find a role by its id and guard name.
     *
     * @param int $id
     * @param string|null $guardName
     *
     * @return \Catname\Permission\Contracts\Role
     *
     * @throws \Catname\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findById(int $id, $guardName): self;

    /**
     * Find or create a role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Catname\Permission\Contracts\Role
     */
    public static function findOrCreate(string $name, $guardName): self;

    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|\Catname\Permission\Contracts\Permission $permission
     *
     * @return bool
     */
    public function hasPermissionTo($permission): bool;
}
